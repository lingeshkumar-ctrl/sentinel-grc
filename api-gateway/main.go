package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// Rate limiting map
var visitors = make(map[string]*rate.Limiter)
var mu sync.Mutex

func getVisitor(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()
	limiter, exists := visitors[ip]
	if !exists {
		// 15 requests per second, burst of 30
		limiter = rate.NewLimiter(15, 30)
		visitors[ip] = limiter
	}
	return limiter
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		limiter := getVisitor(ip)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests - Rate Limit Exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// verifyWithIAM hits the IAM service to ensure real-time session checking
func verifyWithIAM(iamURL, username string) bool {
	verifyURL := fmt.Sprintf("%s/api/auth/verify?username=%s", iamURL, username)
	resp, err := http.Get(verifyURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func authMiddleware(iamURL string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: No token provided", http.StatusUnauthorized)
			return
		}
		
		tokenString := strings.TrimSpace(authHeader)
		for strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
			tokenString = strings.TrimSpace(tokenString)
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		// Real-time revocation check
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Unauthorized: Invalid claims", http.StatusUnauthorized)
			return
		}
		username, ok := claims["sub"].(string)
		if !ok || !verifyWithIAM(iamURL, username) {
			http.Error(w, "Forbidden: Account suspended or deleted", http.StatusForbidden)
			return
		}

		// Inject role and username into request headers
		if role, ok := claims["role"].(string); ok {
			r.Header.Set("X-User-Role", role)
		}
		r.Header.Set("X-User-Name", username)

		next.ServeHTTP(w, r)
	}
}

func rbacMiddleware(allowedRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		allowed := false
		for _, ar := range allowedRoles {
			if role == ar {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Forbidden: Insufficient privileges", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func writeProtect(allowedRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			role := r.Header.Get("X-User-Role")
			allowed := false
			for _, ar := range allowedRoles {
				if role == ar {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Forbidden: Insufficient privileges to perform write action", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func proxyRequest(targetURL string) http.HandlerFunc {
	target, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	secretEnv := os.Getenv("JWT_SECRET")
	if secretEnv != "" {
		jwtSecret = []byte(secretEnv)
	} else {
		jwtSecret = []byte("sentinel_grc_default_dev_key_do_not_use_in_prod")
	}

	iamURL := os.Getenv("IAM_SERVICE_URL")
	if iamURL == "" {
		iamURL = "http://iam-service:8081"
	}
	riskURL := os.Getenv("RISK_SERVICE_URL")
	if riskURL == "" {
		riskURL = "http://risk-service:8000"
	}
	complianceURL := os.Getenv("COMPLIANCE_SERVICE_URL")
	if complianceURL == "" {
		complianceURL = "http://compliance-service:8000"
	}
	scannerURL := os.Getenv("SCANNER_SERVICE_URL")
	if scannerURL == "" {
		scannerURL = "http://scanner-service:8000"
	}
	policyURL := os.Getenv("POLICY_SERVICE_URL")
	if policyURL == "" {
		policyURL = "http://policy-engine:8000"
	}
	telemetryURL := os.Getenv("TELEMETRY_SERVICE_URL")
	if telemetryURL == "" {
		telemetryURL = "http://telemetry-service:8000"
	}
	cryptoURL := os.Getenv("CRYPTO_SERVICE_URL")
	if cryptoURL == "" {
		cryptoURL = "http://crypto-audit:8000"
	}
	soarURL := os.Getenv("SOAR_SERVICE_URL")
	if soarURL == "" {
		soarURL = "http://soar-service:8000"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("API Gateway OK - Deep-Tech Microservices Online"))
	})

	// Public route for login
	mux.HandleFunc("/api/auth/login", rateLimitMiddleware(proxyRequest(iamURL)))

	// IAM User Management
	mux.HandleFunc("/api/users", rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"admin"}, proxyRequest(iamURL)))))
	mux.HandleFunc("/api/users/", rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"admin"}, proxyRequest(iamURL)))))

	// Tenants & Client Organizations
	mux.HandleFunc("/api/tenants", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"admin"}, proxyRequest(iamURL)))))
	mux.HandleFunc("/api/tenants/", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"admin"}, proxyRequest(iamURL)))))

	// Third-Party Vendor Risk (TPRM)
	mux.HandleFunc("/api/vendors", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"manager", "admin"}, proxyRequest(iamURL)))))
	mux.HandleFunc("/api/vendors/", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"manager", "admin"}, proxyRequest(iamURL)))))

	// Cloud Resources & JIT PAM
	mux.HandleFunc("/api/resources", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(iamURL))))
	mux.HandleFunc("/api/resources/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(iamURL))))

	// Risk Service
	mux.HandleFunc("/api/risk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"l1", "l2", "l3", "manager", "admin"}, proxyRequest(riskURL))))(w, r)
		} else if r.Method == http.MethodPost {
			rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"l1", "admin"}, proxyRequest(riskURL))))(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/risk/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/escalate") || strings.HasSuffix(r.URL.Path, "/resolve") {
			rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"l2", "l3", "manager", "admin"}, proxyRequest(riskURL))))(w, r)
		} else if r.Method == http.MethodDelete {
			rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"admin"}, proxyRequest(riskURL))))(w, r)
		} else {
			rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(riskURL)))(w, r)
		}
	})

	mux.HandleFunc("/api/archive", rateLimitMiddleware(authMiddleware(iamURL, rbacMiddleware([]string{"l2", "l3", "manager", "admin"}, proxyRequest(riskURL)))))

	// Compliance Service
	mux.HandleFunc("/api/compliance", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"manager", "admin"}, proxyRequest(complianceURL)))))
	mux.HandleFunc("/api/compliance/", rateLimitMiddleware(authMiddleware(iamURL, writeProtect([]string{"manager", "admin"}, proxyRequest(complianceURL)))))

	// Deep-Tech: Scanner Service
	mux.HandleFunc("/api/scanner/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(scannerURL))))

	// Deep-Tech: Policy-as-Code Engine
	mux.HandleFunc("/api/pac/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(policyURL))))

	// Deep-Tech: SIEM & MITRE ATT&CK Stream
	mux.HandleFunc("/api/siem/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(telemetryURL))))

	// Deep-Tech: Cryptographic SHA-256 Audit Chain
	mux.HandleFunc("/api/crypto/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(cryptoURL))))

	// Deep-Tech: SOAR Autonomous Playbooks
	mux.HandleFunc("/api/soar/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(soarURL))))

	// Deep-Tech: AI Threat & Remediation Copilot
	mux.HandleFunc("/api/copilot/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(soarURL))))

	// Deep-Tech: Threat Actor Intelligence
	mux.HandleFunc("/api/threats/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(soarURL))))

	// Deep-Tech: Continuous Cloud Evidence Feed
	mux.HandleFunc("/api/evidence/", rateLimitMiddleware(authMiddleware(iamURL, proxyRequest(soarURL))))


	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			mu.Lock()
			visitors = make(map[string]*rate.Limiter)
			mu.Unlock()
		}
	}()

	fmt.Printf("API Gateway starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
