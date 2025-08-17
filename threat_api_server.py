from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import os
import tempfile
import asyncio
from datetime import datetime
import logging
from pathlib import Path

# 기존 데이터 처리 시스템 import
from C_part_data_pipeline import MultiFormatThreatNormalizer, ThreatProcessingSystem

# FastAPI 앱 초기화
app = FastAPI(
    title="위협정보 데이터 정제 API",
    description="A파트(다크웹), B파트(텔레그램) 데이터를 수집하여 D파트(대시보드)용 통합 DB 제공",
    version="1.0.0"
)

# CORS 설정 (다른 파트에서 접근 가능하도록)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 도메인만 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 글로벌 변수 초기화 - 기존 파이프라인과 동일한 DB 사용
DB_PATH = 'threat_intelligence.db'  # 기존 파이프라인과 동일
normalizer = MultiFormatThreatNormalizer(
    output_folder='api_processed_data',
    db_path=DB_PATH
)
threat_processor = ThreatProcessingSystem(DB_PATH)

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
        logger.info(f"대량 데이터 수신: {len(data.data)}개 항목 (소스: {data.source})")
        
        # 데이터 정제 및 표준화
        normalized_data = []
        for item in data.data:
            normalized_item = normalizer.normalize_single_item(item)
            # 소스 타입 강제 설정 (A파트: darkweb, B파트: telegram)
            normalized_item['source_type'] = data.source
            normalized_data.append(normalized_item)
        
        # 데이터베이스에 저장 (연관관계 분석 포함)
        stats = normalizer.save_to_database(normalized_data)
        
        logger.info(f"대량 데이터 처리 완료: {stats}")
        
        return ProcessingResponse(
            success=True,
            message="데이터 처리 완료",
            processed_count=len(normalized_data),
            new_posts=stats.get('saved', 0),
            related_posts=0,  # 상세 통계는 별도 API에서 조회
            duplicates=stats.get('duplicates', 0),
            errors=stats.get('errors', 0)
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
        normalized_item = normalizer.normalize_single_item(item_dict)
        
        # 데이터베이스에 저장
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
        if request.search_type == "ioc":
            # IOC 검색
            results = threat_processor.search_ioc_with_relations(
                request.query, 
                ioc_type=None
            )
        elif request.search_type == "author":
            # 작성자 검색
            results = threat_processor.search_by_author_with_timeline(
                request.query, 
                days_back=30
            )
        else:
            # 일반 텍스트 검색 (제목, 내용)
            results = search_content(request.query, request.limit)
        
        return {
            "success": True,
            "query": request.query,
            "search_type": request.search_type,
            "result_count": len(results) if isinstance(results, list) else 1,
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
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if source_type:
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type, threat_type
                FROM threat_posts 
                WHERE source_type = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (source_type, limit))
        else:
            cursor.execute('''
                SELECT id, title, text, author, found_at, source_type, threat_type
                FROM threat_posts 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
        
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
                "threat_type": post[6]
            })
        
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
        
        # 파일 처리
        result = normalizer.process_file(file_path, save_to_db=True)
        
        # 임시 파일 삭제
        os.unlink(file_path)
        
        if result['status'] == 'SUCCESS':
            logger.info(f"백그라운드 처리 완료: {original_filename} - {result['normalized_count']}개 항목")
        else:
            logger.error(f"백그라운드 처리 실패: {original_filename} - {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        logger.error(f"백그라운드 처리 오류 {original_filename}: {e}")

def search_content(query: str, limit: int = 100) -> List[Dict]:
    """
    제목, 내용에서 텍스트 검색
    """
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
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
        "timestamp": datetime.now().isoformat(),
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
        stats = normalizer.get_database_stats()
        return {
            "status": "healthy",
            "database": "connected",
            "total_posts": stats.get('total_posts', 0),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
@app.post("/api/v1/admin/fix-timezone")
async def fix_timezone():
    """기존 데이터의 시간대를 KST로 수정 (1회성)"""
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 각 테이블의 시간 필드를 9시간 더하기
        update_queries = [
            "UPDATE threat_posts SET created_at = datetime(created_at, '+9 hours')",
            "UPDATE threat_posts SET date = datetime(date, '+9 hours') WHERE date IS NOT NULL AND date != ''",
            "UPDATE threat_posts SET found_at = datetime(found_at, '+9 hours') WHERE found_at IS NOT NULL AND found_at != ''",
            "UPDATE threat_iocs SET first_seen = datetime(first_seen, '+9 hours') WHERE first_seen IS NOT NULL",
            "UPDATE post_relationships SET created_at = datetime(created_at, '+9 hours')",
            "UPDATE processing_statistics SET processed_at = datetime(processed_at, '+9 hours')"
        ]
        
        affected_rows = 0
        for query in update_queries:
            cursor.execute(query)
            affected_rows += cursor.rowcount
            logger.info(f"실행됨: {query} - {cursor.rowcount}행 수정")
        
        conn.commit()
        conn.close()
        
        return {
            "success": True, 
            "message": f"총 {affected_rows}개 레코드의 시간을 KST로 수정했습니다",
            "affected_rows": affected_rows
        }
        
    except Exception as e:
        logger.error(f"시간대 수정 오류: {e}")
        raise HTTPException(status_code=500, detail=f"시간대 수정 오류: {str(e)}")
# =============================================================================
# 서버 실행 스크립트
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # 데이터베이스 초기화
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