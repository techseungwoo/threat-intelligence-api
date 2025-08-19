from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import os
import tempfile
import asyncio
from datetime import datetime, timezone, timedelta
import logging
from pathlib import Path
import psycopg2
from urllib.parse import urlparse
# 기존 데이터 처리 시스템 import
from C_part_data_pipeline import MultiFormatThreatNormalizer, ThreatProcessingSystem

# FastAPI 앱 초기화
app = FastAPI(
    title="위협정보 데이터 정제 API",
    description="A파트(다크웹), B파트(텔레그램) 데이터를 수집하여 D파트(대시보드)용 통합 DB 제공",
    version="1.0.0"
)
def get_kst_time():
    """한국 시간 반환"""
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')

# CORS 설정 (다른 파트에서 접근 가능하도록)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 도메인만 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 글로벌 변수 초기화 - 기존 파이프라인과 동일한 DB 사용
# 🔥 DB 연결 방식 자동 감지
DATABASE_URL = os.getenv('DATABASE_URL')  # Railway PostgreSQL

if DATABASE_URL:
    # PostgreSQL 사용 (Railway 환경)
    print("PostgreSQL 사용 (Railway)")
    DB_TYPE = "postgresql"
    DB_PATH = None  # PostgreSQL에서는 사용 안함
else:
    # SQLite 사용 (로컬 환경)
    print("SQLite 사용 (로컬)")
    DB_TYPE = "sqlite"
    DB_PATH = 'threat_intelligence.db'

# 🔥 DB별 초기화
if DB_TYPE == "postgresql":
    # PostgreSQL용 - 임시로 None 설정 (나중에 수정)
    normalizer = None
    threat_processor = None
else:
    # SQLite용 - 기존 방식
    normalizer = MultiFormatThreatNormalizer(
        output_folder='api_processed_data',
        db_path=DB_PATH
    )
    threat_processor = ThreatProcessingSystem(DB_PATH)

def get_db_connection():
    """데이터베이스 연결 함수"""
    try:
        if DB_TYPE == "postgresql":
            if not DATABASE_URL:
                raise Exception("DATABASE_URL이 설정되지 않음")
            return psycopg2.connect(DATABASE_URL)
        else:
            import sqlite3
            return sqlite3.connect(DB_PATH)
    except Exception as e:
        print(f"DB 연결 오류: {e}")
        raise e

def get_postgresql_stats():
    """PostgreSQL용 통계 조회"""
    try:
        conn = get_db_connection()
        
        # PostgreSQL은 with문 사용
        with conn.cursor() as cursor:
            stats = {}
            
            # 기본 통계
            cursor.execute("SELECT COUNT(*) FROM threat_posts")
            result = cursor.fetchone()
            stats['total_posts'] = result[0] if result else 0
            
            # 소스별 분포
            cursor.execute("SELECT source_type, COUNT(*) FROM threat_posts GROUP BY source_type")
            stats['posts_by_source'] = dict(cursor.fetchall())
            
            # 기본값 설정
            stats.update({
                'total_iocs': 0,
                'total_relationships': 0,
                'posts_by_threat_type': {},
                'iocs_by_type': {},
                'top_authors': {},
                'posts_last_7_days': 0
            })
        
        conn.close()
        return stats
        
    except Exception as e:
        print(f"PostgreSQL 통계 조회 오류: {e}")
        return {
            'total_posts': 0,
            'total_iocs': 0,
            'total_relationships': 0,
            'posts_by_source': {},
            'posts_by_threat_type': {},
            'iocs_by_type': {},
            'top_authors': {},
            'posts_last_7_days': 0
        }
def save_postgresql_data(normalized_data: List[Dict]) -> Dict:
    """PostgreSQL용 데이터 저장 함수"""
    try:
        conn = get_db_connection()
        saved_count = 0
        
        with conn.cursor() as cursor:
            for item in normalized_data:
                try:
                    # 중복 체크
                    cursor.execute("SELECT COUNT(*) FROM threat_posts WHERE id = %s", (item.get('thread_id', ''),))
                    if cursor.fetchone()[0] > 0:
                        continue
                    
                    # 데이터 삽입
                    cursor.execute('''
                        INSERT INTO threat_posts 
                        (id, source_type, title, text, author, created_at)
                        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ''', (
                        item.get('thread_id', f"auto-{saved_count}"),
                        item.get('source_type', ''),
                        item.get('title', ''),
                        item.get('text', ''),
                        item.get('author', '')
                    ))
                    saved_count += 1
                except Exception as e:
                    print(f"개별 데이터 저장 오류: {e}")
                    continue
        
        conn.commit()
        conn.close()
        
        return {'saved': saved_count, 'duplicates': 0, 'errors': 0}
        
    except Exception as e:
        print(f"PostgreSQL 데이터 저장 오류: {e}")
        return {'saved': 0, 'duplicates': 0, 'errors': 1}

def normalize_postgresql_item(item: Dict) -> Dict:
    """PostgreSQL용 데이터 정규화 함수 (SQLite와 동일한 매핑 적용)"""
    
    # SQLite와 동일한 필드 매핑 정의
    field_mappings = {
        'thread_id': [
            'thread_id', 'Message ID', 'message_id', 'id', 'msg_id', 'post_id', 'event_id'
        ],
        'url': [
            'url', 'link', 'source_url', 'URL', 'Link'
        ],
        'keyword': [
            'keyword', 'Detected Keywords', 'detected_keywords', 
            'keywords', 'search_terms', 'query', 'Keywords'
        ],
        'found_at': [
            'found_at', 'Timestamp', 'timestamp', 'date_collected',
            'Found At', 'collected_at', 'crawled_at'
        ],
        'title': [
            'title', 'subject', 'headline', 'message_preview', 'Title','event_info'
        ],
        'text': [
            'text', 'Content', 'content', 'preview', 'message', 
            'description', 'hidden_content', 'Message', 'Text'
        ],
        'author': [
            'author', 'Channel', 'channel', 'username', 'user',
            'Author', 'User', 'Username', 'creator_org'
        ],
        'date': [
            'date', 'created_at', 'post_date', 'message_date',
            'Date', 'Created At', 'Post Date', 'event_date'
        ],
        'threat_type': [
            'threat_type', 'Threat Type', 'category', 'type',
            'Category', 'Type', 'threat_category'
        ],
        'platform': [
            'forum', 'platform', 'source_platform', 'site',
            'Forum', 'Platform', 'Source', 'sourcetype'
        ],
        'event_id': [
            'event_id', 'event_id', 'Event ID', 'id'
        ],
        'event_info': [
            'event_info', 'info', 'description'
        ],
        'event_date': [
            'event_date', 'event_timestamp'
        ]
    }
    
    def find_matching_field(data: Dict, target_field: str) -> str:
        """표준 필드에 매핑되는 원본 필드명 찾기"""
        possible_names = field_mappings.get(target_field, [])
        
        for field_name in possible_names:
            if field_name in data:
                return field_name
            
            # 대소문자 구분 없이 검색
            for key in data.keys():
                if key.lower() == field_name.lower():
                    return key
        
        return None
    
    def detect_source_type(data: Dict) -> str:
        """데이터 구조를 분석하여 소스 타입 자동 감지"""
        # MISP 감지 로직
        if 'sourcetype' in data and data['sourcetype'] == 'MISP':
            return 'misp'
        if 'event_id' in data and 'creator_org' in data:
            return 'misp'
        if 'pii_data' in data and 'event_info' in data:
            return 'misp'
        
        # 텔레그램 데이터 특성 확인
        telegram_indicators = [
            'Channel', 'Message ID', 'Threat Type', 'Detected Keywords',
            'channel', 'message_id', 'threat_type', 'detected_keywords'
        ]
        
        # 다크웹 데이터 특성 확인
        darkweb_indicators = [
            'forum', 'thread_id', 'has_hidden_content', 'preview',
            'Forum', 'Thread ID', 'author', 'url'
        ]
        
        telegram_score = sum(1 for indicator in telegram_indicators if indicator in data)
        darkweb_score = sum(1 for indicator in darkweb_indicators if indicator in data)
        
        if telegram_score > darkweb_score:
            return 'telegram'
        elif darkweb_score > telegram_score:
            return 'darkweb'
        else:
            # 기본값 또는 추가 휴리스틱 적용
            if any(indicator in data for indicator in ['Channel', 'Message ID', 'channel']):
                return 'telegram'
            elif any(indicator in data for indicator in ['forum', 'thread_id', 'Forum']):
                return 'darkweb'
            else:
                return 'unknown'
    
    def clean_text(text: Any) -> str:
        """텍스트 정제 및 정규화"""
        if text is None:
            return ""
        
        import re
        text_str = str(text).strip()
        
        # 연속된 공백을 하나로 변환
        text_str = re.sub(r'\s+', ' ', text_str)
        # HTML 태그 제거
        text_str = re.sub(r'<[^>]+>', '', text_str)
        # 줄바꿈 문자를 공백으로 변환
        text_str = text_str.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
        
        return text_str.strip()
    
    # 시작: 정규화 처리
    normalized = {}
    
    # 소스 타입 자동 감지
    source_type = detect_source_type(item)
    normalized['source_type'] = source_type
    
    # 표준 필드들
    standard_fields = [
        'thread_id', 'url', 'keyword', 'found_at', 'title', 'text', 
        'author', 'date', 'threat_type', 'platform', 'event_id', 
        'event_info', 'event_date'
    ]
    
    # 각 표준 필드에 대해 매핑 수행
    for standard_field in standard_fields:
        original_field = find_matching_field(item, standard_field)
        
        if original_field:
            value = item[original_field]
        else:
            value = ""
        
        # 특별 처리가 필요한 필드들
        if standard_field in ['text', 'title']:
            normalized[standard_field] = clean_text(value)
        elif standard_field == 'keyword':
            # 여러 키워드가 쉼표로 구분된 경우 처리
            if value:
                if isinstance(value, str):
                    keywords = value.split(',')
                    normalized[standard_field] = ', '.join([kw.strip() for kw in keywords])
                else:
                    normalized[standard_field] = str(value).strip()
            else:
                normalized[standard_field] = ""
        else:
            normalized[standard_field] = str(value).strip() if value else ""
    
    # 소스별 특별 처리
    if source_type == 'telegram':
        # 텔레그램의 경우 채널명을 author와 platform 둘 다에 설정
        if normalized['author']:
            normalized['platform'] = normalized['author']
    elif source_type == 'darkweb':
        # 다크웹의 경우 숨겨진 콘텐츠 정보 추가
        if 'has_hidden_content' in item and item['has_hidden_content']:
            hidden_content = item.get('hidden_content', '')
            if hidden_content:
                normalized['text'] += f" [Hidden Content: {clean_text(hidden_content)}]"
    elif source_type == 'misp':
        # PII 데이터를 text에 추가
        if 'pii_data' in item and item['pii_data']:
            pii = item['pii_data']
            pii_parts = []
            
            if pii.get('name'):
                pii_parts.append(f"Name: {pii['name']}")
            if pii.get('username'):
                pii_parts.append(f"Username: {pii['username']}")
            if pii.get('email'):
                pii_parts.append(f"Email: {pii['email']}")
            if pii.get('password'):
                pii_parts.append("Password: [REDACTED]")
            if pii.get('phone'):
                pii_parts.append(f"Phone: {pii['phone']}")
            
            if pii_parts:
                current_text = normalized.get('text', '')
                pii_text = ' | '.join(pii_parts)
                normalized['text'] = f"{current_text} [PII: {pii_text}]".strip()
        
        # MISP 기본 설정
        normalized['platform'] = 'MISP'
        normalized['threat_type'] = 'OSINT'
    
    # thread_id가 없는 경우 생성
    if not normalized['thread_id']:
        import uuid
        normalized['thread_id'] = str(uuid.uuid4())[:8]
    
    return normalized

def search_postgresql_author(author: str, limit: int = 100) -> List[Dict]:
    """PostgreSQL용 작성자 검색"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DB_TYPE == "postgresql":
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type, created_at
                FROM threat_posts 
                WHERE author ILIKE %s
                ORDER BY created_at DESC 
                LIMIT %s
            ''', (f'%{author}%', limit))
        else:
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type, created_at
                FROM threat_posts 
                WHERE author LIKE ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (f'%{author}%', limit))
        
        posts = cursor.fetchall()
        conn.close()
        
        results = []
        for post in posts:
            results.append({
                "id": post[0],
                "title": post[1],
                "text": post[2][:200] + "..." if len(post[2]) > 200 else post[2],
                "author": post[3],
                "found_at": post[4],
                "source_type": post[5],
                "created_at": post[6]
            })
        
        return results
        
    except Exception as e:
        print(f"작성자 검색 오류: {e}")
        return []

async def export_as_sqlite():
    """
    PostgreSQL 데이터를 SQLite 파일로 변환
    """
    try:
        import tempfile
        import sqlite3
        
        # 임시 SQLite 파일 생성
        sqlite_file = f"/tmp/threat_db_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        sqlite_conn = sqlite3.connect(sqlite_file)
        sqlite_cursor = sqlite_conn.cursor()
        
        # SQLite 테이블 생성 (기존 구조와 동일)
        sqlite_cursor.execute('''
            CREATE TABLE threat_posts (
                id TEXT PRIMARY KEY,
                source_type TEXT,
                thread_id TEXT,
                url TEXT,
                keyword TEXT,
                found_at TIMESTAMP,
                title TEXT,
                text TEXT,
                author TEXT,
                date TIMESTAMP,
                threat_type TEXT,
                platform TEXT,
                data_hash TEXT,
                created_at TIMESTAMP,
                event_id TEXT,
                event_info TEXT,
                event_date TIMESTAMP
            )
        ''')
        
        # PostgreSQL에서 데이터 조회
        pg_conn = get_db_connection()
        pg_cursor = pg_conn.cursor()
        
        pg_cursor.execute('''
            SELECT id, 
                   COALESCE(source_type, 'unknown') as source_type,
                   COALESCE(id, '') as thread_id,
                   COALESCE(url, '') as url,
                   COALESCE(keyword, 'N/A') as keyword,
                   COALESCE(found_at, created_at) as found_at,
                   COALESCE(title, 'No Title') as title,
                   COALESCE(text, '') as text,
                   COALESCE(author, 'Unknown') as author,
                   COALESCE(date, created_at) as date,
                   COALESCE(threat_type, 'General') as threat_type,
                   COALESCE(platform, source_type) as platform,
                   COALESCE(id, '') as data_hash,
                   created_at,
                   COALESCE(event_id, '') as event_id,
                   COALESCE(event_info, '') as event_info,
                   COALESCE(event_date, created_at) as event_date
            FROM threat_posts
            ORDER BY created_at DESC
        ''')
        
        # SQLite에 데이터 삽입
        rows = pg_cursor.fetchall()
        for row in rows:
            sqlite_cursor.execute('''
                INSERT INTO threat_posts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', row)
        
        pg_conn.close()
        sqlite_conn.commit()
        sqlite_conn.close()
        
        # SQLite 파일 다운로드 제공
        return FileResponse(
            sqlite_file,
            media_type='application/octet-stream',
            filename=f"threat_db_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        )
        
    except Exception as e:
        print(f"SQLite 변환 오류: {e}")
        raise HTTPException(status_code=500, detail=f"SQLite 변환 오류: {str(e)}")        

def init_postgresql_tables():
    """PostgreSQL 테이블 초기화한다"""
    if DB_TYPE != "postgresql":
        return
        
    try:
        conn = get_db_connection()
        
        with conn.cursor() as cursor:
            # threat_posts 테이블 생성
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_posts (
                    id TEXT PRIMARY KEY,
                    source_type TEXT,
                    thread_id TEXT,
                    url TEXT,
                    keyword TEXT,
                    found_at TIMESTAMP,
                    title TEXT,
                    text TEXT,
                    author TEXT,
                    date TIMESTAMP,
                    threat_type TEXT,
                    platform TEXT,
                    data_hash TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_id TEXT,
                    event_info TEXT,
                    event_date TIMESTAMP
                )
            ''')
        
        conn.commit()
        conn.close()
        print("PostgreSQL 테이블 초기화 완료")
        
    except Exception as e:
        print(f"PostgreSQL 초기화 오류: {e}")

# PostgreSQL 환경에서 테이블 초기화
if DB_TYPE == "postgresql":
    init_postgresql_tables()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Pydantic 모델들 (API 요청/응답 구조 정의)
# =============================================================================

class ThreatDataItem(BaseModel):
    """단일 위협정보 데이터 항목"""
    source_type: Optional[str] = None
    thread_id: Optional[str] = None
    url: Optional[str] = None
    keyword: Optional[str] = None
    found_at: Optional[str] = None
    title: Optional[str] = None
    text: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    threat_type: Optional[str] = None
    platform: Optional[str] = None
    event_id: Optional[str] = None
    event_info: Optional[str] = None
    event_date: Optional[str] = None
    pii_data: Optional[Dict[str, Any]] = None

class BulkThreatData(BaseModel):
    """대량 위협정보 데이터"""
    source: str  # 'darkweb' 또는 'telegram'
    data: List[Dict[str, Any]]

class ProcessingResponse(BaseModel):
    """처리 결과 응답"""
    success: bool
    message: str
    processed_count: int
    new_posts: int
    related_posts: int
    duplicates: int
    errors: int
    batch_id: Optional[str] = None

class SearchRequest(BaseModel):
    """검색 요청"""
    query: str
    search_type: str  # 'ioc', 'author', 'content'
    limit: Optional[int] = 100

# =============================================================================
# A파트, B파트용 데이터 수집 엔드포인트
# =============================================================================

@app.post("/api/v1/data/upload/json", response_model=ProcessingResponse)
async def upload_json_data(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: str = "unknown"
):
    """
    A파트, B파트에서 JSON 파일 업로드
    """
    try:
        # 파일 형식 검증
        if not file.filename.endswith('.json'):
            raise HTTPException(status_code=400, detail="JSON 파일만 업로드 가능합니다")
        
        # 임시 파일로 저장
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.json', delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        # 백그라운드에서 처리
        background_tasks.add_task(process_uploaded_file, temp_file_path, source, file.filename)
        
        logger.info(f"JSON 파일 업로드 완료: {file.filename} (소스: {source})")
        
        return ProcessingResponse(
            success=True,
            message=f"파일 업로드 완료. 백그라운드에서 처리 중입니다.",
            processed_count=0,  # 백그라운드 처리이므로 아직 모름
            new_posts=0,
            related_posts=0,
            duplicates=0,
            errors=0
        )
        
    except Exception as e:
        logger.error(f"JSON 업로드 오류: {e}")
        raise HTTPException(status_code=500, detail=f"파일 처리 오류: {str(e)}")

@app.post("/api/v1/data/upload/bulk", response_model=ProcessingResponse)
async def upload_bulk_data(data: BulkThreatData):
    """
    A파트, B파트에서 JSON 데이터를 직접 POST로 전송
    """
    try:
        #소스 타입 검증 
        valid_sources = ['darkweb', 'telegram', 'misp']
        if data.source not in valid_sources:
            raise HTTPException(status_code=400, detail=f"지원되지 않는 소스 타입: {data.source}")
        
        # 배치 처리 설정
        batch_size = 50
        total_items = len(data.data)

        logger.info(f"대량 데이터 수신: {total_items}개 항목 (소스: {data.source})")
        logger.info(f"배치 크기: {batch_size}개씩 처리")
        
        all_stats = {'saved': 0, 'duplicates': 0, 'errors': 0}

        for i in range(0, total_items, batch_size):
            batch_data = data.data[i:i + batch_size]
            logger.info(f"배치 처리 중: {i+1}-{min(i+batch_size, total_items)}/{total_items}")        
            
            # 데이터 정제 및 표준화
            normalized_data = []
            for item in batch_data:
                if DB_TYPE == "postgresql":
                    normalized_item = normalize_postgresql_item(item)
                else:
                    normalized_item = normalizer.normalize_single_item(item)
                
                normalized_item['source_type'] = data.source
                normalized_data.append(normalized_item)
            
            # 데이터베이스에 저장
            if DB_TYPE == "postgresql":
                stats = save_postgresql_data(normalized_data)
            else:
                stats = normalizer.save_to_database(normalized_data)
                
            all_stats['saved'] += stats.get('saved', 0)
            all_stats['duplicates'] += stats.get('duplicates', 0)
            all_stats['errors'] += stats.get('errors', 0)

            if i + batch_size < total_items:
                await asyncio.sleep(2)
                logger.info(f"배치 휴식 : 2초")
                
            logger.info(f"배치 {i // batch_size + 1} 처리 완료: {stats}")
        
        logger.info(f"전체 대량 데이터 처리 완료: {all_stats}")
        
        return ProcessingResponse(
            success=True,
            message="데이터 처리 완료",
            processed_count=total_items,
            new_posts=all_stats.get('saved', 0),
            related_posts=0,
            duplicates=all_stats.get('duplicates', 0),
            errors=all_stats.get('errors', 0)
        )
        
    except Exception as e:
        logger.error(f"대량 데이터 처리 오류: {e}")
        raise HTTPException(status_code=500, detail=f"데이터 처리 오류: {str(e)}")

@app.post("/api/v1/data/upload/single")
async def upload_single_data(item: ThreatDataItem):
    """
    단일 위협정보 데이터 업로드 (테스트용)
    """
    try:
        # Pydantic 모델을 딕셔너리로 변환
        item_dict = item.dict()
        
        # 정제 및 표준화
        if DB_TYPE == "postgresql":
            normalized_item = normalize_postgresql_item(item_dict)
            stats = save_postgresql_data([normalized_item])
        else:
            normalized_item = normalizer.normalize_single_item(item_dict)
            stats = normalizer.save_to_database([normalized_item])
        
        return {
            "success": True,
            "message": "단일 데이터 저장 완료",
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"단일 데이터 처리 오류: {e}")
        raise HTTPException(status_code=500, detail=f"데이터 처리 오류: {str(e)}")

# =============================================================================
# D파트용 데이터 조회 엔드포인트
# =============================================================================

@app.get("/api/v1/data/stats")
async def get_database_stats():
    """
    D파트용 데이터베이스 전체 통계 제공
    """
    try:
        if DB_TYPE == "postgresql":
            stats = get_postgresql_stats()
        else:
            stats = normalizer.get_database_stats()
        return {
            "success": True,
            "data": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"통계 조회 오류: {e}")
        raise HTTPException(status_code=500, detail=f"통계 조회 오류: {str(e)}")

@app.post("/api/v1/data/search")
async def search_threat_data(request: SearchRequest):
    """
    D파트용 위협정보 검색 API
    """
    try:
        # 🔥 모든 검색을 PostgreSQL 기반으로 통일
        if request.search_type == "author":
            results = search_postgresql_author(request.query, request.limit)
        elif request.search_type == "ioc":
            # IOC 검색도 기본 텍스트 검색으로 처리
            results = search_content(request.query, request.limit)
        else:
            # 일반 텍스트 검색
            results = search_content(request.query, request.limit)
        
        return {
            "success": True,
            "query": request.query,
            "search_type": request.search_type,
            "result_count": len(results),
            "data": results
        }
        
    except Exception as e:
        logger.error(f"검색 오류: {e}")
        raise HTTPException(status_code=500, detail=f"검색 오류: {str(e)}")

@app.get("/api/v1/data/recent")
async def get_recent_threats(limit: int = 100, source_type: str = None):
    """
    D파트용 최신 위협정보 조회
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DB_TYPE == "postgresql":
            # PostgreSQL용 쿼리 (%s 사용)
            if source_type:
                cursor.execute('''
                    SELECT id, title, text, author, found_at, source_type, threat_type, 
                            event_id, event_info
                    FROM threat_posts 
                    WHERE source_type = %s
                    ORDER BY created_at DESC 
                    LIMIT %s
                ''', (source_type, limit))
            else:
                cursor.execute('''
                    SELECT id, title, text, author, found_at, source_type, threat_type,
                            event_id, event_info
                    FROM threat_posts 
                    ORDER BY created_at DESC 
                    LIMIT %s
                ''', (limit,))
        else:
            # SQLite용 쿼리 (? 사용)
            if source_type:
                cursor.execute('''
                    SELECT id, title, text, author, found_at, source_type, threat_type, 
                            event_id, event_info
                    FROM threat_posts 
                    WHERE source_type = ?
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (source_type, limit))
            else:
                cursor.execute('''
                    SELECT id, title, text, author, found_at, source_type, threat_type,
                            event_id, event_info
                    FROM threat_posts 
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (limit,))
        
        posts = cursor.fetchall()
        conn.close()
        
        results = []
        for post in posts:
            result_item = {  
                "id": post[0],
                "title": post[1],
                "text": post[2][:200] + "..." if len(post[2]) > 200 else post[2],
                "author": post[3],
                "found_at": post[4],
                "source_type": post[5],
                "threat_type": post[6]
            }  
    
            # 🆕 MISP 데이터인 경우 추가 정보 포함
            if post[5] == 'misp':
                result_item.update({
                    "event_id": post[7],
                    "event_info": post[8]
                })
    
            results.append(result_item)
        
        return {
            "success": True,
            "data": results,
            "count": len(results)
        }
        
    except Exception as e:
        logger.error(f"최신 데이터 조회 오류: {e}")
        raise HTTPException(status_code=500, detail=f"데이터 조회 오류: {str(e)}")

@app.get("/api/v1/data/export/db")
async def export_database():
    """
    D파트용 데이터베이스 파일 다운로드
    """
    try:
        if DB_TYPE == "postgresql":
            # PostgreSQL 데이터베이스를 SQLite로 변환하여 다운로드
            return await export_as_sqlite()
        
        if os.path.exists(DB_PATH):
            return FileResponse(
                DB_PATH,
                media_type='application/octet-stream',
                filename=f"threat_db_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            )
        else:
            raise HTTPException(status_code=404, detail="데이터베이스 파일이 없습니다")
    
    except Exception as e:
        logger.error(f"DB 내보내기 오류: {e}")
        raise HTTPException(status_code=500, detail=f"내보내기 오류: {str(e)}")

# =============================================================================
# 헬퍼 함수들
# =============================================================================

async def process_uploaded_file(file_path: str, source: str, original_filename: str):
    """
    업로드된 파일을 백그라운드에서 처리
    """
    try:
        logger.info(f"백그라운드 처리 시작: {original_filename}")
        
        if DB_TYPE == "postgresql":
            # 🔥 PostgreSQL용 파일 처리 추가
            import json
            
            # JSON 파일 읽기
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 리스트가 아니면 리스트로 변환
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                logger.error(f"지원되지 않는 JSON 형식: {type(data)}")
                return
            
            # 데이터 정규화 및 저장
            normalized_data = []
            for item in data:
                normalized_item = normalize_postgresql_item(item)
                normalized_item['source_type'] = source
                normalized_data.append(normalized_item)
            
            # PostgreSQL에 저장
            stats = save_postgresql_data(normalized_data)
            logger.info(f"PostgreSQL 백그라운드 처리 완료: {original_filename} - {stats['saved']}개 저장")
            
        else:
            # SQLite에서만 기존 파일 처리
            result = normalizer.process_file(file_path, save_to_db=True)
            
            if result['status'] == 'SUCCESS':
                logger.info(f"백그라운드 처리 완료: {original_filename} - {result['normalized_count']}개 항목")
            else:
                logger.error(f"백그라운드 처리 실패: {original_filename} - {result.get('error', 'Unknown error')}")
        
        # 임시 파일 삭제
        os.unlink(file_path)
            
    except Exception as e:
        logger.error(f"백그라운드 처리 오류 {original_filename}: {e}")
        # 오류 발생해도 임시 파일 삭제
        try:
            os.unlink(file_path)
        except:
            pass

def search_content(query: str, limit: int = 100) -> List[Dict]:
    """
    제목, 내용에서 텍스트 검색 (PostgreSQL/SQLite 호환)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DB_TYPE == "postgresql":
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type
                FROM threat_posts 
                WHERE title ILIKE %s OR text ILIKE %s
                ORDER BY created_at DESC 
                LIMIT %s
            ''', (f'%{query}%', f'%{query}%', limit))
        else:
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type
                FROM threat_posts 
                WHERE title LIKE ? OR text LIKE ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', limit))
        
        posts = cursor.fetchall()
        conn.close()
        
        results = []
        for post in posts:
            results.append({
                "id": post[0],
                "title": post[1],
                "text": post[2][:300] + "..." if len(post[2]) > 300 else post[2],
                "author": post[3],
                "found_at": post[4],
                "source_type": post[5]
            })
        
        return results
        
    except Exception as e:
        print(f"검색 오류: {e}")
        return []

# =============================================================================
# 서버 실행 및 상태 확인
# =============================================================================

@app.get("/")
async def root():
    """
    API 서버 상태 확인
    """
    return {
        "service": "위협정보 데이터 정제 API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": get_kst_time(),
        "endpoints": {
            "A파트_B파트용": {
                "JSON파일업로드": "/api/v1/data/upload/json",
                "대량데이터전송": "/api/v1/data/upload/bulk",
                "단일데이터전송": "/api/v1/data/upload/single"
            },
            "D파트용": {
                "통계조회": "/api/v1/data/stats",
                "데이터검색": "/api/v1/data/search",
                "최신데이터": "/api/v1/data/recent",
                "DB다운로드": "/api/v1/data/export/db"
            }
        }
    }

@app.get("/health")
async def health_check():
    """
    헬스 체크
    """
    try:
        if DB_TYPE == "postgresql":
            stats = get_postgresql_stats()
        else:
            stats = normalizer.get_database_stats()
            
        return {
            "status": "healthy",
            "database": "connected",
            "total_posts": stats.get('total_posts', 0),
            "timestamp": get_kst_time()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": get_kst_time()
        }
@app.post("/api/v1/admin/fix-timezone")
async def fix_timezone():
    """기존 데이터의 시간대를 KST로 수정 (1회성)"""
    try:
        if DB_TYPE == "postgresql":
            raise HTTPException(
                status_code=400, 
                detail="PostgreSQL 환경에서는 시간대 수정이 지원되지 않습니다. 데이터베이스에서 직접 수정하세요."
            )
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 먼저 현재 데이터 확인
        cursor.execute("SELECT id, created_at FROM threat_posts LIMIT 3")
        sample_data = cursor.fetchall()
        logger.info(f"샘플 데이터: {sample_data}")
        
        # 더 강력한 업데이트 쿼리 (형식 상관없이)
        update_queries = [
            # threat_posts 테이블
            """UPDATE threat_posts 
               SET created_at = datetime(julianday(created_at) + 0.375)
               WHERE created_at IS NOT NULL""",
            
            """UPDATE threat_posts 
               SET date = datetime(julianday(date) + 0.375)
               WHERE date IS NOT NULL AND date != ''""",
            
            """UPDATE threat_posts 
               SET found_at = datetime(julianday(found_at) + 0.375)
               WHERE found_at IS NOT NULL AND found_at != ''""",
            
            # threat_iocs 테이블
            """UPDATE threat_iocs 
               SET first_seen = datetime(julianday(first_seen) + 0.375)
               WHERE first_seen IS NOT NULL""",
            
            # post_relationships 테이블
            """UPDATE post_relationships 
               SET created_at = datetime(julianday(created_at) + 0.375)
               WHERE created_at IS NOT NULL""",
            
            # processing_statistics 테이블
            """UPDATE processing_statistics 
               SET processed_at = datetime(julianday(processed_at) + 0.375)
               WHERE processed_at IS NOT NULL"""
        ]
        
        total_affected = 0
        for i, query in enumerate(update_queries):
            cursor.execute(query)
            affected = cursor.rowcount
            total_affected += affected
            logger.info(f"쿼리 {i+1}: {affected}행 수정")
        
        conn.commit()
        
        # 수정 후 데이터 확인
        cursor.execute("SELECT id, created_at FROM threat_posts LIMIT 3")
        updated_data = cursor.fetchall()
        logger.info(f"수정 후 데이터: {updated_data}")
        
        conn.close()
        
        return {
            "success": True, 
            "message": f"총 {total_affected}개 레코드의 시간을 KST로 수정했습니다",
            "affected_rows": total_affected,
            "sample_before": sample_data,
            "sample_after": updated_data
        }
        
    except Exception as e:
        logger.error(f"시간대 수정 오류: {e}")
        raise HTTPException(status_code=500, detail=f"시간대 수정 오류: {str(e)}")

@app.post("/api/v1/test/create-dummy")
async def create_dummy_data():
    """영구 저장소 테스트용"""
    try:
        conn = get_db_connection()  # 🔥 변경
        cursor = conn.cursor()
        
        if DB_TYPE == "postgresql":
            # PostgreSQL용 쿼리
            cursor.execute('''
                INSERT INTO threat_posts 
                (id, source_type, title, text, author, created_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ''', ('test-persist-001', 'test', 'Persistence Test', 'This data should survive redeployment', 'test_user'))
        else:
            # SQLite용 쿼리
            cursor.execute('''
                INSERT INTO threat_posts 
                (id, source_type, title, text, author, created_at)
                VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
            ''', ('test-persist-001', 'test', 'Persistence Test', 'This data should survive redeployment', 'test_user'))
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "테스트 데이터 생성 완료", "db_type": DB_TYPE}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/v1/debug/db-status")
async def debug_db_status():
    """데이터베이스 연결 상태 확인"""
    try:
        return {
            "DB_TYPE": DB_TYPE,
            "DATABASE_URL_exists": bool(DATABASE_URL),
            "DATABASE_URL_start": DATABASE_URL[:20] + "..." if DATABASE_URL else None,
            "psycopg2_imported": "psycopg2" in globals(),
        }
    except Exception as e:
        return {"error": str(e)}
# =============================================================================
# 서버 실행 스크립트
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # 데이터베이스 초기화 코드
    if DB_TYPE == "postgresql":
        init_postgresql_tables()
    else:
        threat_processor.init_advanced_database()
    
    print("=== 위협정보 데이터 정제 API 서버 ===")
    print("A파트(다크웹), B파트(텔레그램) → C파트(정제) → D파트(대시보드)")
    print()
    print("서버 주소: http://localhost:8000")
    print("API 문서: http://localhost:8000/docs")
    print("헬스 체크: http://localhost:8000/health")
    print()
    
    # 서버 실행
    uvicorn.run(
        "threat_api_server:app",  # 이 파일명이 threat_api_server.py라고 가정
        host="0.0.0.0",
        port=8000,
        reload=True,  # 개발 중에는 True, 프로덕션에서는 False
        log_level="info"
    )