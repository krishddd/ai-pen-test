"""
AI Security Pipeline v2.0 - Enhanced API Client
================================================

Advanced API client with:
- Circuit breaker pattern
- Rate limiting with token bucket
- Connection pooling
- Exponential backoff retry
- Request fingerprinting
- Metrics collection
"""

import time
import random
import threading
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field
from collections import deque
import requests


@dataclass
class ClientConfig:
    """Configuration for the API client."""
    base_url: str = "http://213.163.75.246:50049"
    model: str = "qwen2.5:7b"
    embedding_model: str = "nomic-embed-text:latest"
    api_key: str = ""
    timeout: int = 30
    max_retries: int = 5
    initial_backoff: float = 1.0
    max_backoff: float = 16.0
    
    # Rate limiting
    rate_limit: float = 10.0  # requests per second
    
    # Circuit breaker
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: int = 30
    
    # Connection pool
    pool_connections: int = 20
    pool_maxsize: int = 20


@dataclass
class APIResponse:
    """Standardized API response container."""
    success: bool
    status_code: int
    response_text: str
    raw_response: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    response_time: float = 0.0
    tokens_used: int = 0


@dataclass
class ClientMetrics:
    """Metrics collected by the client."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens: int = 0
    total_latency: float = 0.0
    error_counts: Dict[str, int] = field(default_factory=dict)
    latency_samples: List[float] = field(default_factory=list)
    
    def record_request(self, success: bool, latency: float, tokens: int = 0, error: str = ""):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error:
                self.error_counts[error] = self.error_counts.get(error, 0) + 1
        self.total_latency += latency
        self.total_tokens += tokens
        self.latency_samples.append(latency)
        # Keep only last 100 samples
        if len(self.latency_samples) > 100:
            self.latency_samples.pop(0)
    
    def get_summary(self) -> Dict[str, Any]:
        avg_latency = self.total_latency / max(1, self.total_requests)
        success_rate = self.successful_requests / max(1, self.total_requests)
        p95_latency = sorted(self.latency_samples)[int(len(self.latency_samples) * 0.95)] if self.latency_samples else 0
        
        return {
            "total_requests": self.total_requests,
            "success_rate": f"{success_rate:.1%}",
            "avg_latency": f"{avg_latency:.2f}s",
            "p95_latency": f"{p95_latency:.2f}s",
            "total_tokens": self.total_tokens,
            "error_breakdown": self.error_counts
        }


class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = self.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0
        self.lock = threading.Lock()
    
    def record_success(self):
        with self.lock:
            self.failure_count = 0
            self.state = self.CLOSED
    
    def record_failure(self):
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = self.OPEN
    
    def can_execute(self) -> bool:
        with self.lock:
            if self.state == self.CLOSED:
                return True
            
            if self.state == self.OPEN:
                # Check if recovery timeout has passed
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = self.HALF_OPEN
                    return True
                return False
            
            # HALF_OPEN - allow one request
            return True
    
    def get_state(self) -> str:
        return self.state


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, rate: float = 10.0):
        self.rate = rate  # tokens per second
        self.tokens = rate
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def acquire(self, timeout: float = 10.0) -> bool:
        """Acquire a token, blocking if necessary."""
        start = time.time()
        
        while True:
            with self.lock:
                now = time.time()
                # Refill tokens
                elapsed = now - self.last_update
                self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
            
            # Check timeout
            if time.time() - start >= timeout:
                return False
            
            # Wait a bit before retrying
            time.sleep(0.1)


# Randomized User-Agent strings for fingerprinting
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "AI-Security-Scanner/2.0",
    "Python-Requests/2.28",
]


class LLMClient:
    """
    Enhanced API client for Ollama-compatible LLM endpoints.
    
    Features:
    - Circuit breaker for fault tolerance
    - Rate limiting to prevent overload
    - Metrics collection for monitoring
    - Request fingerprinting
    """
    
    def __init__(self, config: Optional[ClientConfig] = None):
        self.config = config or ClientConfig()
        
        # Set up session with connection pooling
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.config.pool_connections,
            pool_maxsize=self.config.pool_maxsize,
            max_retries=0  # We handle retries ourselves
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self._update_headers()
        
        # Authenticate with cookie if token provided (for Cloudflare tunnels)
        self._authenticated = False
        if self.config.api_key:
            self._authenticate_with_cookie()
        
        # Initialize components
        self.circuit_breaker = CircuitBreaker(
            self.config.circuit_failure_threshold,
            self.config.circuit_recovery_timeout
        )
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        self.metrics = ClientMetrics()
    
    def _authenticate_with_cookie(self):
        """Authenticate by getting cookie from server (for Cloudflare tunnels)."""
        try:
            auth_url = f"{self.config.base_url}/?token={self.config.api_key}"
            response = self.session.get(auth_url, timeout=10)
            if response.status_code == 200:
                self._authenticated = True
        except Exception:
            pass  # Will fall back to token query param
    
    def _update_headers(self):
        """Update session headers with randomized fingerprint."""
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
        })
    
    def _exponential_backoff(self, attempt: int) -> float:
        """Calculate backoff time with jitter."""
        backoff = self.config.initial_backoff * (2 ** attempt)
        jitter = random.uniform(0, 0.1 * backoff)
        return min(backoff + jitter, self.config.max_backoff)
    
    def _make_request(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> APIResponse:
        """Make an HTTP POST request with all protections."""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            return APIResponse(
                success=False,
                status_code=0,
                response_text="",
                error_message="Circuit breaker is OPEN"
            )
        
        # Rate limiting
        if not self.rate_limiter.acquire(timeout=5):
            return APIResponse(
                success=False,
                status_code=0,
                response_text="",
                error_message="Rate limit exceeded"
            )
        
        url = f"{self.config.base_url}{endpoint}"
        
        # Add token as query parameter only if not authenticated via cookie
        if self.config.api_key and not self._authenticated:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}token={self.config.api_key}"
        
        request_timeout = timeout or self.config.timeout
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                # Randomize headers for each request
                self._update_headers()
                
                start_time = time.time()
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=request_timeout
                )
                response_time = time.time() - start_time
                
                # Parse response
                try:
                    json_response = response.json()
                    response_text = json_response.get("response", "")
                    
                    if not response_text and "message" in json_response:
                        response_text = json_response["message"].get("content", "")
                    
                    # Estimate tokens
                    tokens = len(response_text.split()) + len(payload.get("prompt", "").split())
                    
                except (ValueError, KeyError):
                    json_response = None
                    response_text = response.text
                    tokens = 0
                
                success = response.status_code == 200
                
                # Update circuit breaker
                if success:
                    self.circuit_breaker.record_success()
                else:
                    self.circuit_breaker.record_failure()
                
                # Record metrics
                self.metrics.record_request(
                    success=success,
                    latency=response_time,
                    tokens=tokens,
                    error="" if success else f"HTTP_{response.status_code}"
                )
                
                return APIResponse(
                    success=success,
                    status_code=response.status_code,
                    response_text=response_text,
                    raw_response=json_response,
                    response_time=response_time,
                    tokens_used=tokens
                )
                
            except requests.exceptions.Timeout:
                last_error = "Request timed out"
            except requests.exceptions.ConnectionError:
                last_error = "Connection failed"
            except requests.exceptions.RequestException as e:
                last_error = str(e)
            
            # Record failure
            self.circuit_breaker.record_failure()
            self.metrics.record_request(
                success=False,
                latency=0,
                error=last_error
            )
            
            # Backoff before retry
            if attempt < self.config.max_retries - 1:
                time.sleep(self._exponential_backoff(attempt))
        
        return APIResponse(
            success=False,
            status_code=0,
            response_text="",
            error_message=f"Failed after {self.config.max_retries} attempts: {last_error}"
        )
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        timeout: Optional[int] = None,
        stream: bool = False
    ) -> APIResponse:
        """Send a generation request."""
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": stream
        }
        if system_prompt:
            payload["system"] = system_prompt
        
        return self._make_request("/api/generate", payload, timeout)
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        timeout: Optional[int] = None,
        stream: bool = False
    ) -> APIResponse:
        """Send a chat request."""
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": stream
        }
        return self._make_request("/api/chat", payload, timeout)
    
    def batch_generate(
        self,
        prompts: List[str],
        max_concurrent: int = 5
    ) -> List[APIResponse]:
        """Generate responses for multiple prompts concurrently."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = [None] * len(prompts)
        
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_idx = {
                executor.submit(self.generate, prompt): idx
                for idx, prompt in enumerate(prompts)
            }
            
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = APIResponse(
                        success=False,
                        status_code=0,
                        response_text="",
                        error_message=str(e)
                    )
        
        return results
    
    def embed(self, text: str, timeout: int = 10) -> APIResponse:
        """Get embeddings for text."""
        payload = {
            "model": self.config.embedding_model,
            "prompt": text
        }
        return self._make_request("/api/embeddings", payload, timeout)
    
    def health_check(self) -> Tuple[bool, str]:
        """Verify service health using GET /api/tags first, then POST test."""
        # First try GET /api/tags (Ollama's list models endpoint)
        url = f"{self.config.base_url}/api/tags"
        if self.config.api_key:
            url = f"{url}?token={self.config.api_key}"
        
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                return True, f"Service healthy. Response time: {response_time:.2f}s"
            elif response.status_code == 405:
                # Try POST /api/generate as fallback
                gen_response = self.generate("Hi", timeout=15)
                if gen_response.success:
                    return True, f"Service healthy. Response time: {gen_response.response_time:.2f}s"
                else:
                    return False, f"Service unhealthy: {gen_response.error_message or f'HTTP {gen_response.status_code}'}"
            else:
                return False, f"Service unhealthy: HTTP {response.status_code}"
        except Exception as e:
            return False, f"Service unhealthy: {str(e)}"
    
    def check_embedding_model(self) -> Tuple[bool, str]:
        """Check embedding model availability."""
        response = self.embed("test", timeout=10)
        
        if response.success:
            return True, "Embedding model available"
        else:
            return False, f"Embedding model unavailable: {response.error_message or 'Unknown error'}"
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get client performance metrics."""
        return {
            **self.metrics.get_summary(),
            "circuit_breaker_state": self.circuit_breaker.get_state()
        }
    
    def reset_metrics(self):
        """Reset all metrics."""
        self.metrics = ClientMetrics()
    
    def send_raw(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> APIResponse:
        """Send raw request to any endpoint."""
        return self._make_request(endpoint, payload, timeout)


def create_client(
    base_url: str = "http://213.163.75.246:50049",
    model: str = "qwen2.5:7b",
    api_key: str = "",
    timeout: int = 30
) -> LLMClient:
    """Create a configured LLM client."""
    config = ClientConfig(
        base_url=base_url,
        model=model,
        api_key=api_key,
        timeout=timeout
    )
    return LLMClient(config)


def load_config_from_yaml(config_path: str) -> ClientConfig:
    """Load client config from YAML file."""
    try:
        import yaml
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
        
        target = data.get("target", {})
        client = data.get("client", {})
        auth = data.get("authentication", {})
        
        return ClientConfig(
            base_url=target.get("base_url", "http://213.163.75.246:50049"),
            model=target.get("model", "qwen2.5:7b"),
            embedding_model=target.get("embedding_model", "nomic-embed-text:latest"),
            api_key=auth.get("api_key", ""),
            timeout=client.get("timeout", 30),
            max_retries=client.get("max_retries", 5),
            rate_limit=client.get("rate_limit", 10),
            circuit_failure_threshold=client.get("circuit_breaker", {}).get("failure_threshold", 5),
            circuit_recovery_timeout=client.get("circuit_breaker", {}).get("recovery_timeout", 30),
            pool_connections=client.get("connection_pool_size", 20),
            pool_maxsize=client.get("connection_pool_size", 20),
        )
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return ClientConfig()
