import json
import csv
import os
import glob
import re
import pandas as pd
import logging
import sqlite3
import hashlib
import uuid
from difflib import SequenceMatcher
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from collections import defaultdict

class ThreatProcessingSystem:
    
    def __init__(self, db_path: str = 'threat_intelligence.db'):
        self.db_path = db_path
        self.setup_logging()
        
    def setup_logging(self):
        #로깅 설정
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('threat_processing.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def get_local_time(self):
        
        kst = timezone(timedelta(hours=9))
        return datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')

    # ==========================================================================
    # 데이터베이스 초기화 및 스키마 설계
    # ==========================================================================
    
    def init_advanced_database(self):
        #연관관계를 지원하는 고급 데이터베이스 스키마 초기화
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. 메인 위협정보 게시물 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_posts (
                id TEXT PRIMARY KEY,              -- 고유 게시물 ID
                source_type TEXT NOT NULL,        -- 소스 타입 (telegram/darkweb)
                thread_id TEXT,                   -- 원본 스레드/메시지 ID
                url TEXT,                         -- 게시물 URL
                keyword TEXT,                     -- 검색 키워드
                found_at TIMESTAMP,               -- 발견 시간
                title TEXT,                       -- 게시물 제목
                text TEXT,                        -- 게시물 내용
                author TEXT,                      -- 작성자/채널명
                date TIMESTAMP,                   -- 작성일
                threat_type TEXT,                 -- 위협 유형
                platform TEXT,                    -- 플랫폼 정보
                data_hash TEXT UNIQUE,            -- 중복 검사용 해시
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))  -- DB 저장 시간
            )
        ''')
        
        # 2. IOC(위협지표) 정보 테이블 - 각 IOC를 별도로 관리
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id TEXT NOT NULL,            -- 연결된 게시물 ID
                ioc_type TEXT NOT NULL,           -- IOC 타입 (email, ip, hash 등)
                ioc_value TEXT NOT NULL,          -- IOC 실제 값
                context TEXT,                     -- IOC가 발견된 맥락
                confidence REAL DEFAULT 1.0,     -- 신뢰도 (0.0 ~ 1.0)
                first_seen TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (post_id) REFERENCES threat_posts(id) ON DELETE CASCADE
            )
        ''')
        
        # 3. 게시물 간 연관관계 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id_1 TEXT NOT NULL,          -- 첫 번째 게시물 ID
                post_id_2 TEXT NOT NULL,          -- 두 번째 게시물 ID
                relationship_type TEXT NOT NULL,   -- 관계 타입
                similarity_score REAL,            -- 유사도 점수 (0.0 ~ 1.0)
                description TEXT,                 -- 관계 설명
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (post_id_1) REFERENCES threat_posts(id) ON DELETE CASCADE,
                FOREIGN KEY (post_id_2) REFERENCES threat_posts(id) ON DELETE CASCADE,
                UNIQUE(post_id_1, post_id_2)     -- 중복 관계 방지
            )
        ''')
        
        # 4. 처리 통계 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processing_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT,                    -- 배치 처리 ID
                source_files TEXT,                -- 처리된 소스 파일들
                total_input INTEGER,              -- 입력 데이터 수
                new_posts INTEGER,                -- 새로 생성된 게시물
                related_posts INTEGER,            -- 연관관계로 처리된 게시물
                duplicate_posts INTEGER,          -- 완전 중복 게시물
                error_count INTEGER,              -- 오류 발생 수
                processing_time_seconds REAL,    -- 처리 시간
                processed_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
            )
        ''')
        
        # 5. 성능 최적화를 위한 인덱스 생성
        indexes = [
            # 기본 검색 인덱스
            "CREATE INDEX IF NOT EXISTS idx_threat_posts_source_type ON threat_posts(source_type)",
            "CREATE INDEX IF NOT EXISTS idx_threat_posts_threat_type ON threat_posts(threat_type)",
            "CREATE INDEX IF NOT EXISTS idx_threat_posts_author ON threat_posts(author)",
            "CREATE INDEX IF NOT EXISTS idx_threat_posts_found_at ON threat_posts(found_at)",
            "CREATE INDEX IF NOT EXISTS idx_threat_posts_data_hash ON threat_posts(data_hash)",
            
            # IOC 검색 최적화 인덱스
            "CREATE INDEX IF NOT EXISTS idx_threat_iocs_value ON threat_iocs(ioc_value)",
            "CREATE INDEX IF NOT EXISTS idx_threat_iocs_type ON threat_iocs(ioc_type)",
            "CREATE INDEX IF NOT EXISTS idx_threat_iocs_post_id ON threat_iocs(post_id)",
            "CREATE INDEX IF NOT EXISTS idx_threat_iocs_value_type ON threat_iocs(ioc_value, ioc_type)",
            
            # 연관관계 검색 최적화 인덱스
            "CREATE INDEX IF NOT EXISTS idx_post_relationships_post1 ON post_relationships(post_id_1)",
            "CREATE INDEX IF NOT EXISTS idx_post_relationships_post2 ON post_relationships(post_id_2)",
            "CREATE INDEX IF NOT EXISTS idx_post_relationships_type ON post_relationships(relationship_type)",
            "CREATE INDEX IF NOT EXISTS idx_post_relationships_similarity ON post_relationships(similarity_score)"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except sqlite3.OperationalError as e:
                if "already exists" not in str(e):
                    self.logger.warning(f"인덱스 생성 실패: {e}")
        
        conn.commit()
        conn.close()
        self.logger.info(f"고급 데이터베이스 스키마 초기화 완료: {self.db_path}")

    # ==========================================================================
    # IOC(위협지표) 추출 시스템
    # ==========================================================================
    
    def extract_threat_indicators(self, text: str, title: str = "") -> Dict[str, List[Dict]]:
        """
        텍스트에서 다양한 위협 지표(IOC) 추출
        
        Args:
            text: 분석할 텍스트 내용
            title: 게시물 제목 (선택적)
            
        Returns:
            IOC 타입별로 분류된 딕셔너리
            각 IOC는 value, context, position 정보를 포함
        """
        full_text = f"{title} {text}".strip()
        
        # IOC 결과 저장용 딕셔너리 초기화
        indicators = {
            'emails': [],           # 이메일 주소
            'ips': [],              # IP 주소
            'domains': [],          # 도메인명
            'urls': [],             # URL
            'file_hashes': [],      # 파일 해시값
            'crypto_addresses': [], # 암호화폐 주소
            'leaked_accounts': [],  # 유출된 계정명
            'phone_numbers': []     # 전화번호
        }
        
        if not full_text:
            return indicators
        
        # 1. 이메일 주소 추출 (다양한 난독화 패턴 지원)
        email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',           # 일반 이메일
            r'\b[A-Za-z0-9._%+-]+\s*\[at\]\s*[A-Za-z0-9.-]+\s*\[dot\]\s*[A-Z|a-z]{2,}\b',  # [at], [dot] 난독화
            r'\b[A-Za-z0-9._%+-]+\s*\(@\)\s*[A-Za-z0-9.-]+\s*\(\.\)\s*[A-Z|a-z]{2,}\b'     # (@), (.) 난독화
        ]
        
        for pattern in email_patterns:
            for match in re.finditer(pattern, full_text, re.IGNORECASE):
                email = match.group()
                # 난독화 해제
                cleaned_email = email.replace('[at]', '@').replace('[dot]', '.').replace('(@)', '@').replace('(.)', '.')
                cleaned_email = re.sub(r'\s+', '', cleaned_email).lower()
                
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['emails'].append({
                    'value': cleaned_email,
                    'context': context,
                    'position': match.start(),
                    'original_format': email  # 원본 난독화 형태 보존
                })
        
        # 2. IP 주소 추출 (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, full_text):
            ip = match.group()
            # 사설 IP 제외 옵션 (필요시 주석 해제)
            # if self.is_private_ip(ip):
            #     continue
            context = self.extract_context(full_text, match.start(), match.end())
            indicators['ips'].append({
                'value': ip,
                'context': context,
                'position': match.start()
            })
        
        # 3. 도메인명 추출
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        for match in re.finditer(domain_pattern, full_text.lower()):
            domain = match.group()
            # 이메일 도메인과 중복 제거
            if not any(email_item['value'].endswith(domain) for email_item in indicators['emails']):
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['domains'].append({
                    'value': domain,
                    'context': context,
                    'position': match.start()
                })
        
        # 4. URL 추출
        url_patterns = [
            r'https?://[^\s<>"\'{}|\\^`\[\]]+',    # HTTP/HTTPS URL
            r'ftp://[^\s<>"\'{}|\\^`\[\]]+',       # FTP URL
            r'www\.[^\s<>"\'{}|\\^`\[\]]+'         # www.로 시작하는 URL
        ]
        
        for pattern in url_patterns:
            for match in re.finditer(pattern, full_text):
                url = match.group()
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['urls'].append({
                    'value': url,
                    'context': context,
                    'position': match.start()
                })
        
        # 5. 파일 해시값 추출 (MD5, SHA1, SHA256, SHA512)
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', 'md5'),      # MD5
            (r'\b[a-fA-F0-9]{40}\b', 'sha1'),     # SHA1
            (r'\b[a-fA-F0-9]{64}\b', 'sha256'),   # SHA256
            (r'\b[a-fA-F0-9]{128}\b', 'sha512')   # SHA512
        ]
        
        for pattern, hash_type in hash_patterns:
            for match in re.finditer(pattern, full_text):
                hash_value = match.group().lower()
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['file_hashes'].append({
                    'value': hash_value,
                    'context': context,
                    'position': match.start(),
                    'hash_type': hash_type
                })
        
        # 6. 암호화폐 주소 추출
        crypto_patterns = [
            (r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', 'bitcoin'),     # 비트코인
            (r'\b0x[a-fA-F0-9]{40}\b', 'ethereum'),                  # 이더리움
            (r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b', 'litecoin')    # 라이트코인
        ]
        
        for pattern, crypto_type in crypto_patterns:
            for match in re.finditer(pattern, full_text):
                crypto_addr = match.group()
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['crypto_addresses'].append({
                    'value': crypto_addr,
                    'context': context,
                    'position': match.start(),
                    'crypto_type': crypto_type
                })
        
        # 7. 유출된 계정 정보 추출
        account_patterns = [
            r'(?:user|username|login|account|id)[:\s=]+([a-zA-Z0-9._-]{3,})',         # user: username 형태
            r'(?:admin|administrator)[:\s=]+([a-zA-Z0-9._-]{3,})',                   # admin: username 형태
            r'([a-zA-Z0-9._-]{3,})\s*:\s*[^\s\n]{3,}',                               # username:password 형태
            r'(?:credential|cred)[:\s]+([a-zA-Z0-9._-]{3,})'                         # credential: username 형태
        ]
        
        for pattern in account_patterns:
            for match in re.finditer(pattern, full_text, re.IGNORECASE):
                account = match.group(1) if match.groups() else match.group()
                # 이메일의 사용자명 부분 제외
                if '@' not in account and len(account) >= 3:
                    context = self.extract_context(full_text, match.start(), match.end())
                    indicators['leaked_accounts'].append({
                        'value': account,
                        'context': context,
                        'position': match.start()
                    })
        
        # 8. 전화번호 추출
        phone_patterns = [
            r'\+?[1-9]\d{1,14}',                    # 국제 형식
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',   # 미국 형식
            r'\b010[-.\s]?\d{4}[-.\s]?\d{4}\b'      # 한국 형식
        ]
        
        for pattern in phone_patterns:
            for match in re.finditer(pattern, full_text):
                phone = match.group()
                context = self.extract_context(full_text, match.start(), match.end())
                indicators['phone_numbers'].append({
                    'value': phone,
                    'context': context,
                    'position': match.start()
                })
        
        # 중복 제거 및 정렬
        for ioc_type in indicators:
            # 값 기준으로 중복 제거
            seen_values = set()
            unique_indicators = []
            for item in indicators[ioc_type]:
                if item['value'] not in seen_values:
                    seen_values.add(item['value'])
                    unique_indicators.append(item)
            
            # 위치 순으로 정렬
            indicators[ioc_type] = sorted(unique_indicators, key=lambda x: x['position'])
        
        self.logger.info(f"IOC 추출 완료: {sum(len(v) for v in indicators.values())}개 지표 발견")
        return indicators
    
    def extract_context(self, text: str, start: int, end: int, context_length: int = 80) -> str:
        """
        IOC 주변의 맥락 정보 추출
        
        Args:
            text: 전체 텍스트
            start: IOC 시작 위치
            end: IOC 끝 위치
            context_length: 앞뒤로 추출할 문자 수
            
        Returns:
            IOC 주변 맥락 문자열
        """
        context_start = max(0, start - context_length)
        context_end = min(len(text), end + context_length)
        context = text[context_start:context_end].strip()
        
        # 줄바꿈을 공백으로 변환하고 연속 공백 제거
        context = re.sub(r'\s+', ' ', context)
        
        return context

    # ==========================================================================
    # 유사도 계산 및 연관관계 분석
    # ==========================================================================
    
    def calculate_content_similarity(self, data1: Dict, data2: Dict) -> float:
        """
        두 게시물 간의 전체 콘텐츠 유사도 계산
        
        Args:
            data1, data2: 비교할 게시물 데이터
            
        Returns:
            유사도 점수 (0.0 ~ 1.0)
        """
        # 필드별 가중치 설정
        field_weights = {
            'title': 0.3,     # 제목 30%
            'text': 0.5,      # 내용 50%
            'author': 0.2     # 작성자 20%
        }
        
        total_similarity = 0.0
        total_weight = 0.0
        
        for field, weight in field_weights.items():
            text1 = str(data1.get(field, '')).strip()
            text2 = str(data2.get(field, '')).strip()
            
            if text1 and text2:
                # 두 가지 유사도 측정 방법 사용
                
                # 1. 문자 시퀀스 유사도 (편집 거리 기반)
                sequence_similarity = SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
                
                # 2. TF-IDF 코사인 유사도 (단어 빈도 기반)
                try:
                    vectorizer = TfidfVectorizer(
                        stop_words='english',  # 영어 불용어 제거
                        ngram_range=(1, 2),    # 1-gram, 2-gram 사용
                        max_features=1000      # 최대 특성 수 제한
                    )
                    tfidf_matrix = vectorizer.fit_transform([text1, text2])
                    tfidf_similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
                except Exception as e:
                    # TF-IDF 계산 실패시 시퀀스 유사도만 사용
                    self.logger.warning(f"TF-IDF 계산 실패: {e}")
                    tfidf_similarity = sequence_similarity
                
                # 두 방법의 가중 평균 (시퀀스 40%, TF-IDF 60%)
                field_similarity = (sequence_similarity * 0.4) + (tfidf_similarity * 0.6)
                
                total_similarity += field_similarity * weight
                total_weight += weight
        
        final_similarity = total_similarity / total_weight if total_weight > 0 else 0.0
        return min(1.0, max(0.0, final_similarity))  # 0.0 ~ 1.0 범위로 제한
    
    def calculate_ioc_difference_ratio(self, iocs1: Dict, iocs2: Dict) -> float:
        """
        두 게시물의 IOC 차이 비율 계산
        
        Args:
            iocs1, iocs2: 비교할 IOC 딕셔너리
            
        Returns:
            IOC 차이 비율 (0.0 = 완전 동일, 1.0 = 완전 다름)
        """
        total_difference = 0.0
        field_count = 0
        
        # 주요 IOC 타입들만 비교
        important_ioc_types = ['emails', 'ips', 'file_hashes', 'leaked_accounts', 'crypto_addresses']
        
        for ioc_type in important_ioc_types:
            values1 = set([item['value'] for item in iocs1.get(ioc_type, [])])
            values2 = set([item['value'] for item in iocs2.get(ioc_type, [])])
            
            if values1 or values2:  # 적어도 하나에 값이 있는 경우만
                intersection = len(values1 & values2)  # 교집합
                union = len(values1 | values2)         # 합집합
                
                # Jaccard 거리 계산 (1 - Jaccard 유사도)
                difference = 1 - (intersection / union) if union > 0 else 1
                total_difference += difference
                field_count += 1
        
        return total_difference / field_count if field_count > 0 else 0.0

    # ==========================================================================
    # 연관관계 기반 데이터 저장 시스템
    # ==========================================================================
    
    def save_with_relationship_detection(self, normalized_data: List[Dict]) -> Dict[str, int]:
        """
        연관관계 감지를 포함한 스마트 데이터 저장
        
        Args:
            normalized_data: 정규화된 데이터 리스트
            
        Returns:
            처리 통계 딕셔너리
        """
        stats = {
            'inserted': 0,              # 새로 저장된 독립 게시물
            'related_created': 0,       # 연관관계와 함께 저장된 게시물
            'exact_duplicates': 0,      # 완전 중복으로 무시된 게시물
            'errors': 0                 # 오류 발생 건수
        }
        
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        for i, item in enumerate(normalized_data):
            try:
                self.logger.info(f"처리 중: {i+1}/{len(normalized_data)} - {item.get('title', 'Unknown')[:50]}...")
                
                # 1. IOC 추출
                iocs = self.extract_threat_indicators(
                    item.get('text', ''), 
                    item.get('title', '')
                )
                
                # 2. 완전 중복 체크
                if self.is_exact_duplicate(item):
                    stats['exact_duplicates'] += 1
                    self.logger.info("완전 중복으로 건너뜀")
                    continue
                
                # 3. 유사한 기존 게시물 검색
                similar_posts = self.find_similar_existing_posts(item, iocs)
                
                if similar_posts:
                    # 4-1. 연관관계를 포함한 저장
                    post_id = self.save_new_post_with_relations(item, iocs, similar_posts)
                    if post_id:
                        stats['related_created'] += 1
                        self.logger.info(f"연관관계 포함 저장 완료: {len(similar_posts)}개 관련 게시물")
                else:
                    # 4-2. 독립적인 새 게시물 저장
                    post_id = self.save_new_post(item, iocs)
                    if post_id:
                        stats['inserted'] += 1
                        self.logger.info("새 독립 게시물 저장 완료")
                        
            except Exception as e:
                stats['errors'] += 1
                self.logger.error(f"데이터 저장 오류: {e}")
        
        # 5. 처리 통계 저장
        processing_time = (datetime.now() - start_time).total_seconds()
        self.save_processing_statistics(batch_id, stats, processing_time, normalized_data)
        
        self.logger.info(f"배치 처리 완료: {stats}")
        return stats
    
    def find_similar_existing_posts(self, new_data: Dict, new_iocs: Dict, 
                                   similarity_threshold: float = 0.8,
                                   ioc_difference_threshold: float = 0.3,
                                   days_back: int = 30) -> List[Tuple[str, float]]:
        """
        새 데이터와 유사한 기존 게시물 검색
        
        Args:
            new_data: 새로운 게시물 데이터
            new_iocs: 새로운 게시물의 IOC
            similarity_threshold: 콘텐츠 유사도 임계값
            ioc_difference_threshold: IOC 차이 임계값
            days_back: 검색할 과거 일수
            
        Returns:
            (게시물_ID, 유사도_점수) 튜플 리스트
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # 같은 소스 타입의 최근 게시물들 조회 (성능 최적화)
            cursor.execute('''
                SELECT id, title, text, author, found_at FROM threat_posts 
                WHERE source_type = ? 
                AND created_at > datetime('now', '-{} days')
                AND author = ?
                ORDER BY created_at DESC
                LIMIT 1000
            '''.format(days_back), (new_data.get('source_type', ''), new_data.get('author', '')))
            
            existing_posts = cursor.fetchall()
            self.logger.info(f"비교 대상 게시물: {len(existing_posts)}개")
            
            similar_posts = []
            
            for post_id, title, text, author, found_at in existing_posts:
                existing_data = {
                    'title': title or '',
                    'text': text or '',
                    'author': author or ''
                }
                
                # 1. 콘텐츠 유사도 계산
                content_similarity = self.calculate_content_similarity(new_data, existing_data)
                
                if content_similarity >= similarity_threshold:
                    # 2. IOC 차이 계산
                    existing_iocs = self.get_post_iocs(post_id)
                    ioc_difference = self.calculate_ioc_difference_ratio(new_iocs, existing_iocs)
                    
                    if ioc_difference >= ioc_difference_threshold:
                        # 유사하지만 IOC가 충분히 다름 - 연관관계 후보
                        similar_posts.append((post_id, content_similarity))
                        self.logger.info(f"연관관계 후보 발견: ID={post_id}, 유사도={content_similarity:.3f}, IOC차이={ioc_difference:.3f}")
            
            # 유사도 순으로 정렬 (높은 순)
            similar_posts.sort(key=lambda x: x[1], reverse=True)
            
            return similar_posts[:5]  # 최대 5개까지만 반환
            
        except Exception as e:
            self.logger.error(f"유사 게시물 검색 오류: {e}")
            return []
        finally:
            conn.close()
    
    def save_new_post_with_relations(self, data: Dict, iocs: Dict, 
                                   similar_posts: List[Tuple[str, float]]) -> Optional[str]:
        """
        연관관계와 함께 새 게시물 저장
        
        Args:
            data: 게시물 데이터
            iocs: 추출된 IOC 정보
            similar_posts: 유사한 기존 게시물들 [(post_id, similarity_score), ...]
            
        Returns:
            저장된 게시물 ID (성공시) 또는 None (실패시)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # 1. 새 게시물 저장
            import uuid
            post_id = str(uuid.uuid4())
            data_hash = self.generate_data_hash(data)
            local_time = self.get_local_time()

            cursor.execute('''
                INSERT INTO threat_posts 
                (id, source_type, thread_id, url, keyword, found_at, title, text, 
                 author, date, threat_type, platform, data_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                post_id, data.get('source_type', ''), data.get('thread_id', ''), 
                data.get('url', ''), data.get('keyword', ''), data.get('found_at', ''),
                data.get('title', ''), data.get('text', ''), data.get('author', ''),
                data.get('date', ''), data.get('threat_type', ''), data.get('platform', ''),
                data_hash, local_time
            ))
            
            # 2. IOC 정보 저장
            self.save_post_iocs(cursor, post_id, iocs)
            
            # 3. 연관관계 저장
            for similar_post_id, similarity_score in similar_posts:
                # 양방향 관계 생성 방지를 위해 ID 순서 정렬
                if post_id < similar_post_id:
                    pid1, pid2 = post_id, similar_post_id
                else:
                    pid1, pid2 = similar_post_id, post_id
                
                cursor.execute('''
                    INSERT OR IGNORE INTO post_relationships 
                    (post_id_1, post_id_2, relationship_type, similarity_score, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    pid1, pid2, 
                    'similar_content_different_ioc', 
                    similarity_score,
                    f"유사한 내용이지만 서로 다른 IOC를 포함하는 게시물들"
                ))
            
            conn.commit()
            self.logger.info(f"연관관계 포함 게시물 저장 완료: {post_id} (연관: {len(similar_posts)}개)")
            return post_id
            
        except Exception as e:
            conn.rollback()
            self.logger.error(f"연관관계 저장 오류: {e}")
            return None
        finally:
            conn.close()
    
    def save_new_post(self, data: Dict, iocs: Dict) -> Optional[str]:
        """
        독립적인 새 게시물 저장
        
        Args:
            data: 게시물 데이터
            iocs: 추출된 IOC 정보
            
        Returns:
            저장된 게시물 ID (성공시) 또는 None (실패시)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            import uuid
            post_id = str(uuid.uuid4())
            data_hash = self.generate_data_hash(data)
            local_time = self.get_local_time()

            cursor.execute('''
                INSERT INTO threat_posts 
                (id, source_type, thread_id, url, keyword, found_at, title, text, 
                 author, date, threat_type, platform, data_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                post_id, data.get('source_type', ''), data.get('thread_id', ''), 
                data.get('url', ''), data.get('keyword', ''), data.get('found_at', ''),
                data.get('title', ''), data.get('text', ''), data.get('author', ''),
                data.get('date', ''), data.get('threat_type', ''), data.get('platform', ''),
                data_hash, local_time
            ))
            
            # IOC 정보 저장
            self.save_post_iocs(cursor, post_id, iocs)
            
            conn.commit()
            self.logger.info(f"새 독립 게시물 저장 완료: {post_id}")
            return post_id
            
        except Exception as e:
            conn.rollback()
            self.logger.error(f"게시물 저장 오류: {e}")
            return None
        finally:
            conn.close()
    
    def save_post_iocs(self, cursor, post_id: str, iocs: Dict):
        """
        게시물의 IOC 정보를 데이터베이스에 저장
        
        Args:
            cursor: 데이터베이스 커서
            post_id: 게시물 ID
            iocs: IOC 딕셔너리
        """
        local_time = self.get_local_time()

        # IOC 타입 매핑 (내부 키 -> DB 저장용 타입명)
        ioc_type_mapping = {
            'emails': 'email_address',
            'ips': 'ip_address', 
            'domains': 'domain',
            'urls': 'url',
            'file_hashes': 'file_hash',
            'crypto_addresses': 'crypto_address',
            'leaked_accounts': 'leaked_account',
            'phone_numbers': 'phone_number'
        }
        
        ioc_count = 0
        for ioc_category, db_type in ioc_type_mapping.items():
            for ioc_item in iocs.get(ioc_category, []):
                cursor.execute('''
                    INSERT INTO threat_iocs (post_id, ioc_type, ioc_value, context, confidence, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    post_id, 
                    db_type, 
                    ioc_item['value'], 
                    ioc_item.get('context', ''),
                    1.0,  # 기본 신뢰도
                    local_time
                ))
                ioc_count += 1
        
        self.logger.debug(f"IOC 저장 완료: {ioc_count}개")

    # ==========================================================================
    # 헬퍼 메서드들
    # ==========================================================================
    
    def generate_data_hash(self, data: Dict[str, Any]) -> str:
        """
        데이터 중복 검사를 위한 해시 생성
        
        Args:
            data: 해시를 생성할 데이터
            
        Returns:
            MD5 해시 문자열
        """
        # 중복 검사에 사용할 핵심 필드들
        key_fields = ['source_type', 'thread_id', 'title', 'text', 'author']
        hash_content = ''.join([str(data.get(field, '')) for field in key_fields])
        return hashlib.md5(hash_content.encode('utf-8')).hexdigest()
    
    def is_exact_duplicate(self, data: Dict) -> bool:
        """
        완전 중복 데이터 체크
        
        Args:
            data: 체크할 데이터
            
        Returns:
            중복 여부 (True/False)
        """
        data_hash = self.generate_data_hash(data)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM threat_posts WHERE data_hash = ?', (data_hash,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count > 0
    
    def get_post_iocs(self, post_id: str) -> Dict[str, List[Dict]]:
        """
        특정 게시물의 IOC 정보 조회
        
        Args:
            post_id: 게시물 ID
            
        Returns:
            IOC 딕셔너리 (extract_threat_indicators와 동일한 형태)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ioc_type, ioc_value, context FROM threat_iocs 
            WHERE post_id = ?
        ''', (post_id,))
        
        ioc_records = cursor.fetchall()
        conn.close()
        
        # DB 타입명을 내부 키로 역매핑
        type_reverse_mapping = {
            'email_address': 'emails',
            'ip_address': 'ips',
            'domain': 'domains',
            'url': 'urls',
            'file_hash': 'file_hashes',
            'crypto_address': 'crypto_addresses',
            'leaked_account': 'leaked_accounts',
            'phone_number': 'phone_numbers'
        }
        
        iocs = {key: [] for key in type_reverse_mapping.values()}
        
        for ioc_type, ioc_value, context in ioc_records:
            internal_key = type_reverse_mapping.get(ioc_type, 'unknown')
            if internal_key != 'unknown':
                iocs[internal_key].append({
                    'value': ioc_value,
                    'context': context,
                    'position': 0  # DB에서 조회시 위치 정보 없음
                })
        
        return iocs
    
    def save_processing_statistics(self, batch_id: str, stats: Dict, 
                                 processing_time: float, input_data: List):
        """
        처리 통계 정보 저장
        
        Args:
            batch_id: 배치 처리 ID
            stats: 처리 통계
            processing_time: 처리 시간 (초)
            input_data: 입력 데이터
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO processing_statistics 
                (batch_id, total_input, new_posts, related_posts, duplicate_posts, 
                 error_count, processing_time_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                batch_id,
                len(input_data),
                stats['inserted'],
                stats['related_created'], 
                stats['exact_duplicates'],
                stats['errors'],
                processing_time
            ))
            
            conn.commit()
            self.logger.info(f"처리 통계 저장 완료: {batch_id}")
            
        except Exception as e:
            self.logger.error(f"통계 저장 오류: {e}")
        finally:
            conn.close()

    # ==========================================================================
    # 고급 검색 시스템
    # ==========================================================================
    
    def search_ioc_with_relations(self, ioc_value: str, ioc_type: str = None) -> List[Dict]:
        """
        IOC로 검색하되 연관 게시물도 함께 반환
        
        Args:
            ioc_value: 검색할 IOC 값
            ioc_type: IOC 타입 (선택적, 없으면 모든 타입에서 검색)
            
        Returns:
            검색 결과 리스트 (연관 게시물 정보 포함)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # IOC가 포함된 게시물 직접 검색
            if ioc_type:
                cursor.execute('''
                    SELECT DISTINCT p.id, p.title, p.text, p.author, p.found_at, 
                           p.source_type, p.threat_type, p.platform
                    FROM threat_posts p
                    JOIN threat_iocs i ON p.id = i.post_id
                    WHERE i.ioc_value = ? AND i.ioc_type = ?
                    ORDER BY p.found_at DESC
                ''', (ioc_value.lower(), ioc_type))
            else:
                cursor.execute('''
                    SELECT DISTINCT p.id, p.title, p.text, p.author, p.found_at,
                           p.source_type, p.threat_type, p.platform
                    FROM threat_posts p
                    JOIN threat_iocs i ON p.id = i.post_id
                    WHERE i.ioc_value = ?
                    ORDER BY p.found_at DESC
                ''', (ioc_value.lower(),))
            
            direct_matches = cursor.fetchall()
            
            results = []
            processed_posts = set()  # 중복 방지
            
            for post_id, title, text, author, found_at, source_type, threat_type, platform in direct_matches:
                if post_id in processed_posts:
                    continue
                processed_posts.add(post_id)
                
                # 연관 게시물 검색
                related_posts = self.get_related_posts(cursor, post_id)
                
                # 해당 게시물의 모든 IOC 조회
                post_iocs = self.get_post_iocs(post_id)
                
                results.append({
                    'post_id': post_id,
                    'title': title,
                    'text': text,
                    'author': author,
                    'found_at': found_at,
                    'source_type': source_type,
                    'threat_type': threat_type,
                    'platform': platform,
                    'iocs': post_iocs,
                    'related_posts': related_posts,
                    'match_reason': f"IOC '{ioc_value}' 직접 발견"
                })
            
            self.logger.info(f"IOC 검색 완료: '{ioc_value}' - {len(results)}개 결과")
            return results
            
        except Exception as e:
            self.logger.error(f"IOC 검색 오류: {e}")
            return []
        finally:
            conn.close()
    
    def get_related_posts(self, cursor, post_id: str) -> List[Dict]:
        """
        특정 게시물의 연관 게시물들 조회
        
        Args:
            cursor: 데이터베이스 커서
            post_id: 기준 게시물 ID
            
        Returns:
            연관 게시물 정보 리스트
        """
        cursor.execute('''
            SELECT p.id, p.title, p.author, p.found_at, r.similarity_score, r.relationship_type
            FROM post_relationships r
            JOIN threat_posts p ON (
                CASE 
                    WHEN r.post_id_1 = ? THEN p.id = r.post_id_2
                    WHEN r.post_id_2 = ? THEN p.id = r.post_id_1
                    ELSE 0
                END
            )
            WHERE r.post_id_1 = ? OR r.post_id_2 = ?
            ORDER BY r.similarity_score DESC
        ''', (post_id, post_id, post_id, post_id))
        
        related_data = cursor.fetchall()
        
        related_posts = []
        for rel_id, rel_title, rel_author, rel_found_at, similarity, rel_type in related_data:
            related_posts.append({
                'id': rel_id,
                'title': rel_title,
                'author': rel_author,
                'found_at': rel_found_at,
                'similarity_score': similarity,
                'relationship_type': rel_type
            })
        
        return related_posts
    
    def search_by_author_with_timeline(self, author: str, days_back: int = 30) -> Dict:
        """
        작성자별 활동 타임라인 검색
        
        Args:
            author: 검색할 작성자명
            days_back: 검색할 과거 일수
            
        Returns:
            작성자 활동 정보 및 타임라인
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # 작성자의 게시물들 조회
            cursor.execute('''
                SELECT id, title, found_at, threat_type, platform
                FROM threat_posts 
                WHERE author = ? 
                AND found_at > datetime('now', '-{} days')
                ORDER BY found_at DESC
            '''.format(days_back), (author,))
            
            posts = cursor.fetchall()
            
            if not posts:
                return {'author': author, 'posts': [], 'total_posts': 0, 'unique_iocs': 0}
            
            # 작성자의 모든 IOC 수집
            all_iocs = set()
            post_details = []
            
            for post_id, title, found_at, threat_type, platform in posts:
                post_iocs = self.get_post_iocs(post_id)
                
                # 모든 IOC 값 수집
                for ioc_list in post_iocs.values():
                    for ioc in ioc_list:
                        all_iocs.add(ioc['value'])
                
                post_details.append({
                    'id': post_id,
                    'title': title,
                    'found_at': found_at,
                    'threat_type': threat_type,
                    'platform': platform,
                    'ioc_count': sum(len(ioc_list) for ioc_list in post_iocs.values())
                })
            
            return {
                'author': author,
                'total_posts': len(posts),
                'unique_iocs': len(all_iocs),
                'date_range': f"{posts[-1][2]} ~ {posts[0][2]}",
                'posts': post_details
            }
            
        except Exception as e:
            self.logger.error(f"작성자 검색 오류: {e}")
            return {'author': author, 'posts': [], 'total_posts': 0, 'unique_iocs': 0}
        finally:
            conn.close()
    
    def get_database_statistics(self) -> Dict:
        """
        데이터베이스 전체 통계 조회
        
        Returns:
            통계 정보 딕셔너리
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            stats = {}
            
            # 기본 통계
            cursor.execute("SELECT COUNT(*) FROM threat_posts")
            stats['total_posts'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM threat_iocs")
            stats['total_iocs'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM post_relationships")
            stats['total_relationships'] = cursor.fetchone()[0]
            
            # 소스별 분포
            cursor.execute("SELECT source_type, COUNT(*) FROM threat_posts GROUP BY source_type")
            stats['posts_by_source'] = dict(cursor.fetchall())
            
            # 위협 유형별 분포
            cursor.execute("SELECT threat_type, COUNT(*) FROM threat_posts GROUP BY threat_type")
            stats['posts_by_threat_type'] = dict(cursor.fetchall())
            
            # IOC 타입별 분포
            cursor.execute("SELECT ioc_type, COUNT(*) FROM threat_iocs GROUP BY ioc_type")
            stats['iocs_by_type'] = dict(cursor.fetchall())
            
            # 활성 작성자 TOP 10
            cursor.execute('''
                SELECT author, COUNT(*) as post_count 
                FROM threat_posts 
                WHERE author IS NOT NULL AND author != ''
                GROUP BY author 
                ORDER BY post_count DESC 
                LIMIT 10
            ''')
            stats['top_authors'] = dict(cursor.fetchall())
            
            # 최근 활동 통계 (7일)
            cursor.execute('''
                SELECT COUNT(*) FROM threat_posts 
                WHERE created_at > datetime('now', '-7 days')
            ''')
            stats['posts_last_7_days'] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            self.logger.error(f"통계 조회 오류: {e}")
            return {}
        finally:
            conn.close()












class MultiFormatThreatNormalizer:
    #JSON, CSV 등 다양한 형식의 위협정보 데이터를 표준화하는 클래스

    def __init__(self, output_folder: str = 'normalized_threat_data', db_path: str = 'threat_intelligence.db'):
        self.output_folder = output_folder
        self.db_path = db_path
        self.setup_logging() 
        self.create_output_folder()
        self.threat_processor = ThreatProcessingSystem(db_path)
        self.threat_processor.init_advanced_database()


        # 통합 표준 필드 정의
        self.standard_fields = {
            'source_type': '',      # 'telegram' 또는 'darkweb'
            'thread_id': '',        # 고유 식별자
            'url': '',              # 링크/URL
            'keyword': '',          # 검색 키워드/탐지된 키워드
            'found_at': '',         # 발견 시간
            'title': '',            # 제목/메시지 요약
            'text': '',             # 내용
            'author': '',           # 작성자/채널명
            'date': '',             # 작성일/타임스탬프
            'threat_type': '',      # 위협 유형
            'platform': ''          # 플랫폼 정보 (포럼명/채널명)
        }

        # 소스별 필드 매핑 정의
        self.field_mappings = self._create_field_mappings()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
        )
        self.logger = logging.getLogger(__name__)
    
    def create_output_folder(self):
        Path(self.output_folder).mkdir(parents=True, exist_ok=True)
        self.logger.info(f'출력 폴더 생성: {self.output_folder}')
    
    def _create_field_mappings(self) -> Dict[str, List[str]]:
        #다양한 소스의 필드명 매핑 정의
        return {
            'thread_id': [
                'thread_id', 'Message ID', 'message_id', 'id', 'msg_id', 'post_id'
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
                'title', 'subject', 'headline', 'message_preview', 'Title'
            ],
            'text': [
                'text', 'Content', 'content', 'preview', 'message', 
                'description', 'hidden_content', 'Message', 'Text'
            ],
            'author': [
                'author', 'Channel', 'channel', 'username', 'user',
                'Author', 'User', 'Username'
            ],
            'date': [
                'date', 'created_at', 'post_date', 'message_date',
                'Date', 'Created At', 'Post Date'
            ],
            'threat_type': [
                'threat_type', 'Threat Type', 'category', 'type',
                'Category', 'Type', 'threat_category'
            ],
            'platform': [
                'forum', 'platform', 'source_platform', 'site',
                'Forum', 'Platform', 'Source'
            ]
        }

    def load_csv_data(self, file_path: str) -> List[Dict[str, Any]]:
        #CSV 파일을 딕셔너리 리스트로 로드
        try:
            # pandas를 사용하여 CSV 로드 (다양한 인코딩 시도)
            encodings = ['utf-8', 'utf-8-sig', 'cp949', 'euc-kr', 'latin-1']
            
            for encoding in encodings:
                try:
                    df = pd.read_csv(file_path, encoding=encoding)
                    self.logger.info(f"CSV 로드 성공 (인코딩: {encoding}): {file_path}")
                    
                    # DataFrame을 딕셔너리 리스트로 변환
                    data = df.to_dict('records')
                    
                    # NaN 값을 빈 문자열로 변환
                    for record in data:
                        for key, value in record.items():
                            if pd.isna(value):
                                record[key] = ""
                    
                    self.logger.info(f"CSV 데이터 로드 완료: {len(data)}개 레코드")
                    return data
                    
                except UnicodeDecodeError:
                    continue
                    
            raise Exception("지원되는 인코딩으로 파일을 읽을 수 없습니다.")
            
        except Exception as e:
            self.logger.error(f"CSV 파일 로드 오류 {file_path}: {e}")
            return []

    def load_json_data(self, file_path: str) -> List[Dict[str, Any]]:
        #JSON 파일에서 데이터 로드
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # JSON 데이터가 리스트가 아닌 경우 리스트로 변환
            if isinstance(data, dict):
                if 'data' in data and isinstance(data['data'], list):
                    return data['data']
                else:
                    return [data]
            elif isinstance(data, list):
                return data
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"JSON 파일 로드 오류 {file_path}: {e}")
            return []

    def detect_source_type(self, data: Dict[str, Any]) -> str:
        #데이터 구조를 분석하여 소스 타입 자동 감지
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

    def find_matching_field(self, data: Dict[str, Any], target_field: str) -> Optional[str]:
        #표준 필드에 매핑되는 원본 필드명 찾기
        possible_names = self.field_mappings.get(target_field, [])

        for field_name in possible_names:
            if field_name in data:
                return field_name
            
            # 대소문자 구분 없이 검색
            for key in data.keys():
                if key.lower() == field_name.lower():
                    return key
        
        return None
    
    def clean_text(self, text: Any) -> str:
        #텍스트 정제 및 정규화
        if text is None or pd.isna(text):
            return ""

        text_str = str(text).strip()
        
        # 연속된 공백을 하나로 변환
        text_str = re.sub(r'\s+', ' ', text_str)
        # HTML 태그 제거
        text_str = re.sub(r'<[^>]+>', '', text_str)
        # 줄바꿈 문자를 공백으로 변환
        text_str = text_str.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

        return text_str.strip()

    def normalize_single_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        #단일 데이터 항목을 표준 구조로 변환
        normalized = {}
        
        # 소스 타입 자동 감지
        source_type = self.detect_source_type(item)
        normalized['source_type'] = source_type
        
        # 각 표준 필드에 대해 매핑 수행
        for standard_field in self.standard_fields:
            if standard_field == 'source_type':
                continue  # 이미 설정됨
                
            original_field = self.find_matching_field(item, standard_field)
            
            if original_field:
                value = item[original_field]
            else:
                value = ""
            
            # 특별 처리가 필요한 필드들
            if standard_field in ['text', 'title']:
                normalized[standard_field] = self.clean_text(value)
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
            elif standard_field == 'date':
                # 날짜 형식 통일
                normalized[standard_field] = self.normalize_date(str(value) if value else "")
            else:
                normalized[standard_field] = str(value).strip() if value and not pd.isna(value) else ""
        
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
                    normalized['text'] += f" [Hidden Content: {self.clean_text(hidden_content)}]"
        
        # thread_id가 없는 경우 생성
        if not normalized['thread_id']:
            import uuid
            normalized['thread_id'] = str(uuid.uuid4())[:8]
            self.logger.warning(f"thread_id 생성: {normalized['thread_id']}")
        
        return normalized

    def normalize_date(self, date_str: str) -> str:
    
        if not date_str or pd.isna(date_str) or str(date_str).strip() == '':
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 현재 시간으로 기본값
    
        date_str = str(date_str).strip()
    
    # 다양한 날짜 패턴 지원 (기존보다 확장)
        patterns = [
            ('%Y-%m-%d %H:%M:%S', r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
            ('%Y-%m-%d', r'\d{4}-\d{2}-\d{2}'),
            ('%m/%d/%Y', r'\d{1,2}/\d{1,2}/\d{4}'),
            ('%Y/%m/%d', r'\d{4}/\d{1,2}/\d{1,2}'),
            ('%d-%m-%Y', r'\d{1,2}-\d{1,2}-\d{4}'),
            ('%Y.%m.%d', r'\d{4}\.\d{1,2}\.\d{1,2}'),
        ]
    
        for date_format, pattern in patterns:
            if re.match(pattern, date_str):
                try:
                    parsed_date = datetime.strptime(date_str, date_format)
                    return parsed_date.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
    
    # 파싱 실패시 현재 시간 반환
        self.logger.warning(f"날짜 파싱 실패, 현재 시간 사용: {date_str}")
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def process_file(self, input_file: str, save_to_db: bool = False) -> Dict[str, Any]:
        """파일을 처리하여 표준화된 데이터 생성 (JSON, CSV 지원)"""
        try:
            file_extension = os.path.splitext(input_file)[1].lower()
            
            # 파일 형식에 따라 로드 방법 선택
            if file_extension == '.csv':
                raw_data = self.load_csv_data(input_file)
                if not raw_data:
                    raise Exception("CSV 파일을 로드할 수 없습니다.")
            elif file_extension == '.json':
                raw_data = self.load_json_data(input_file)
                if not raw_data:
                    raise Exception("JSON 파일을 로드할 수 없습니다.")
            else:
                raise Exception(f"지원되지 않는 파일 형식: {file_extension}")

            normalized_items = []
            
            # 각 데이터 항목 표준화
            for item in raw_data:
                if isinstance(item, dict):
                    normalized_item = self.normalize_single_item(item)
                    normalized_items.append(normalized_item)

            # 출력 파일 생성 (항상 JSON으로 저장)
            input_filename = os.path.splitext(os.path.basename(input_file))[0]
            output_filename = f"normalized_{input_filename}.json"
            output_path = os.path.join(self.output_folder, output_filename)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(normalized_items, f, ensure_ascii=False, indent=2)

            result = {
                'status': 'SUCCESS',
                'input_file': input_file,
                'input_format': file_extension[1:],  # '.csv' -> 'csv'
                'output_file': output_path,
                'original_count': len(raw_data),
                'normalized_count': len(normalized_items),
                'detected_sources': list(set(item['source_type'] for item in normalized_items))
            }

            # 데이터베이스에 저장
            if save_to_db:
                db_result = self.save_to_database(normalized_items)
                result['database_saved'] = db_result['saved']
                result['database_duplicates'] = db_result['duplicates']
                result['database_errors'] = db_result['errors']

            self.logger.info(f'파일 처리 완료: {input_file} -> {output_path}')
            return result
        
        except Exception as e:
            error_result = {
                'status': 'ERROR',
                'input_file': input_file,
                'error': str(e)
            }
            self.logger.error(f'파일 처리 실패: {input_file}: {e}')
            return error_result

    def process_folder(self, input_folder: str, save_to_db: bool = False) -> List[Dict[str, Any]]:
        #폴더 내 모든 JSON/CSV 파일 일괄 처리
        # JSON과 CSV 파일 모두 찾기
        json_files = glob.glob(os.path.join(input_folder, "*.json"))
        csv_files = glob.glob(os.path.join(input_folder, "*.csv"))
        all_files = json_files + csv_files
        
        if not all_files:
            self.logger.warning(f"JSON/CSV 파일이 없습니다: {input_folder}")
            return []
        
        self.logger.info(f"처리 시작: {len(all_files)}개 파일 (JSON: {len(json_files)}, CSV: {len(csv_files)})")
        
        results = []
        success_count = 0
        error_count = 0
        all_sources = set()
        format_stats = defaultdict(int)
        
        for file_path in all_files:
            result = self.process_file(file_path, save_to_db)
            results.append(result)
            
            if result['status'] == 'SUCCESS':
                success_count += 1
                all_sources.update(result['detected_sources'])
                format_stats[result['input_format']] += 1
            else:
                error_count += 1
        
        self.logger.info(f"처리 완료: 성공 {success_count}개, 실패 {error_count}개")
        self.logger.info(f"파일 형식별 통계: {dict(format_stats)}")
        self.logger.info(f"감지된 소스 타입: {', '.join(all_sources)}")
        
        return results
    
    def save_to_database(self, normalized_data: List[Dict[str, Any]]) -> Dict[str, int]:
    
        if not normalized_data:
            self.logger.warning("저장할 데이터가 없습니다.")
            return {'saved': 0, 'errors': 0}
    
        try:
            # ThreatProcessingSystem의 저장 메서드 호출
            stats = self.threat_processor.save_with_relationship_detection(normalized_data)
        
            self.logger.info(f"데이터베이스 저장 완료: {stats}")
            return {
                'saved': stats.get('inserted', 0) + stats.get('related_created', 0),
                'duplicates': stats.get('exact_duplicates', 0),
                'errors': stats.get('errors', 0)
            }
        
        except Exception as e:
            self.logger.error(f"데이터베이스 저장 오류: {e}")
            return {'saved': 0, 'errors': 1}

    def get_database_stats(self) -> Dict:
        #데이터베이스 통계 조회
        return self.threat_processor.get_database_statistics()







def main():
    print("=== 다중 형식 위협정보 데이터 표준화 도구 ===")
    print("지원 형식: JSON, CSV")
    
    normalizer = MultiFormatThreatNormalizer()
    
    while True:
        print("\n1. 폴더 처리 (JSON/CSV 파일들 일괄 변환)")
        print("2. 단일 파일 처리") 
        print("3. 데이터베이스 통계 조회")
        print("4. 종료")
        
        choice = input("선택하세요 (1-4): ").strip()
        
        if choice == "1":
            input_folder = input("입력 폴더 경로: ").strip()
            save_to_db = input("데이터베이스에 저장하시겠습니까? (y/n): ").strip().lower() == 'y'
            if not os.path.exists(input_folder):
                print(f"폴더가 존재하지 않습니다: {input_folder}")
                continue
            
            results = normalizer.process_folder(input_folder, save_to_db)
            
            # 결과 요약
            success_results = [r for r in results if r['status'] == 'SUCCESS']
            error_results = [r for r in results if r['status'] == 'ERROR']
            
            print(f"\n=== 처리 결과 ===")
            print(f"총 파일: {len(results)}개")
            print(f"성공: {len(success_results)}개") 
            print(f"실패: {len(error_results)}개")
            print(f"출력 폴더: {normalizer.output_folder}")
            
            # 파일 형식별 통계
            format_stats = defaultdict(int)
            for result in success_results:
                format_stats[result.get('input_format', 'unknown')] += 1
            
            if format_stats:
                print(f"처리된 파일 형식: {dict(format_stats)}")
            
            # 소스 타입별 통계
            all_sources = set()
            for result in success_results:
                all_sources.update(result.get('detected_sources', []))
            
            if all_sources:
                print(f"감지된 데이터 소스: {', '.join(all_sources)}")
            
            if error_results:
                print("\n실패한 파일들:")
                for error in error_results:
                    print(f"  - {error['input_file']}: {error['error']}")
        
        elif choice == "2":
            input_file = input("입력 파일 경로 (JSON 또는 CSV): ").strip()
            save_to_db = input("데이터베이스에 저장하시겠습니까? (y/n): ").strip().lower() == 'y'

            if not os.path.exists(input_file):
                print(f"파일이 존재하지 않습니다: {input_file}")
                continue
            
            file_ext = os.path.splitext(input_file)[1].lower()
            if file_ext not in ['.json', '.csv']:
                print(f"지원되지 않는 파일 형식입니다: {file_ext}")
                print("지원 형식: .json, .csv")
                continue
            
            result = normalizer.process_file(input_file, save_to_db)
            
            print(f"\n=== 처리 결과 ===")
            if result['status'] == 'SUCCESS':
                print(f"상태: 성공")
                print(f"입력 파일: {result['input_file']}")
                print(f"입력 형식: {result['input_format'].upper()}")
                print(f"출력 파일: {result['output_file']}")
                print(f"원본 항목 수: {result['original_count']}")
                print(f"변환된 항목 수: {result['normalized_count']}")
                print(f"감지된 소스: {', '.join(result['detected_sources'])}")
            else:
                print(f"상태: 실패")
                print(f"오류: {result['error']}")

        elif choice == "3":
            stats = normalizer.get_database_stats()
            print(f"\n=== 데이터베이스 통계 ===")
            print(f"총 게시물 수 : {stats.get('total_posts', 0)}")
            print(f"총 IOC 수 : {stats.get('total_iocs', 0)}")
            print(f"총 관계 수 : {stats.get('total_relationships', 0)}")
            print(f"게시물 소스별 분포: {stats.get('posts_by_source', {})}")
            print(f"게시물 위협 유형별 분포: {stats.get('posts_by_threat_type', {})}")
            print(f"IOC 타입별 분포: {stats.get('iocs_by_type', {})}")
            print(f"활성 작성자 TOP 10: {stats.get('top_authors', {})}")
            print(f"최근 7일간 게시물 수: {stats.get('posts_last_7_days', 0)}") 
        
        elif choice == "4":
            print("프로그램을 종료합니다.")
            break
        
        else:
            print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()