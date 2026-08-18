package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID             int     `json:"id"`
	Username       string  `json:"username"`
	Role           string  `json:"role"`
	SuspendedUntil *string `json:"suspended_until"`
}

type Tenant struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Tier       string `json:"tier"` // Enterprise, Financial-Grade, Standard
	SLA        string `json:"sla"`  // 99.99%, 99.9%
	SeatLimit  int    `json:"seat_limit"`
	ActiveUsers int   `json:"active_users"`
	CreatedAt  string `json:"created_at"`
}

type Vendor struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Category         string `json:"category"` // Cloud Infrastructure, Payment Gateway, Observability, Collaboration
	Criticality      string `json:"criticality"` // Tier 1, Tier 2, Tier 3
	InherentRisk     int    `json:"inherent_risk"` // 1-5
	ResidualRisk     int    `json:"residual_risk"` // 1-5
	SOC2Certified    bool   `json:"soc2_certified"`
	ISO27001Certified bool  `json:"iso27001_certified"`
	DPASigned        bool   `json:"dpa_signed"`
	NextReviewDate   string `json:"next_review_date"`
	Notes            string `json:"notes"`
}

type CloudResource struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	AssetType   string `json:"asset_type"` // Kubernetes Cluster, PostgreSQL DB, S3 Storage Vault, API Gateway, VPC Subnet
	Environment string `json:"environment"` // Production, Staging, Sandbox
	Sensitivity string `json:"sensitivity"` // Confidential, PCI-DSS, HIPAA, Public
	Owner       string `json:"owner"`
}

type ResourceAllocation struct {
	ID           int    `json:"id"`
	UserID       int    `json:"user_id"`
	Username     string `json:"username"`
	ResourceID   int    `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	Permission   string `json:"permission"` // Read, Operator, Admin, Auditor
	GrantedAt    string `json:"granted_at"`
}

type JITRequest struct {
	ID            int     `json:"id"`
	UserID        int     `json:"user_id"`
	Username      string  `json:"username"`
	ResourceID    int     `json:"resource_id"`
	ResourceName  string  `json:"resource_name"`
	RequestedRole string  `json:"requested_role"` // Emergency Root, Database Admin, Security Auditor
	Justification string  `json:"justification"`
	TicketRef     string  `json:"ticket_ref"`
	TTLMinutes    int     `json:"ttl_minutes"`
	Status        string  `json:"status"` // PENDING, APPROVED, REJECTED, EXPIRED
	ExpiresAt     *string `json:"expires_at"`
	ApprovedBy    *string `json:"approved_by"`
	CreatedAt     string  `json:"created_at"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type SuspendRequest struct {
	SuspendedUntil string `json:"suspended_until"`
}

type RoleRequest struct {
	Role string `json:"role"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

var db *sql.DB
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func initDB() {
	var err error
	os.MkdirAll("/app/data", os.ModePerm)
	db, err = sql.Open("sqlite", "/app/data/iam.db")
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
	}

	// 1. Users Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'employee',
			suspended_until DATETIME
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	// 2. Tenants Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tenants (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			tier TEXT NOT NULL DEFAULT 'Enterprise',
			sla TEXT NOT NULL DEFAULT '99.9%',
			seat_limit INTEGER NOT NULL DEFAULT 50,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create tenants table: %v", err)
	}

	// 3. Vendors Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vendors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			category TEXT NOT NULL,
			criticality TEXT NOT NULL DEFAULT 'Tier 2',
			inherent_risk INTEGER NOT NULL DEFAULT 3,
			residual_risk INTEGER NOT NULL DEFAULT 2,
			soc2_certified BOOLEAN NOT NULL DEFAULT 1,
			iso27001_certified BOOLEAN NOT NULL DEFAULT 1,
			dpa_signed BOOLEAN NOT NULL DEFAULT 1,
			next_review_date TEXT NOT NULL,
			notes TEXT
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create vendors table: %v", err)
	}

	// 4. Cloud Resources Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS cloud_resources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			asset_type TEXT NOT NULL,
			environment TEXT NOT NULL,
			sensitivity TEXT NOT NULL,
			owner TEXT NOT NULL
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create cloud_resources table: %v", err)
	}

	// 5. Resource Allocations Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS resource_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			resource_id INTEGER NOT NULL,
			permission TEXT NOT NULL DEFAULT 'Read',
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, resource_id)
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create resource_allocations table: %v", err)
	}

	// 6. JIT Access Requests Table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS jit_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			resource_id INTEGER NOT NULL,
			requested_role TEXT NOT NULL,
			justification TEXT NOT NULL,
			ticket_ref TEXT NOT NULL,
			ttl_minutes INTEGER NOT NULL DEFAULT 60,
			status TEXT NOT NULL DEFAULT 'PENDING',
			expires_at DATETIME,
			approved_by TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create jit_requests table: %v", err)
	}

	// Seed bootstrap Admin
	initialUsername := os.Getenv("INITIAL_ADMIN_USERNAME")
	if initialUsername == "" {
		initialUsername = "admin"
	}
	initialPassword := os.Getenv("INITIAL_ADMIN_PASSWORD")
	if initialPassword == "" {
		initialPassword = "admin123"
	}

	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
		db.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, initialUsername, string(hash), "admin")
		fmt.Printf("Bootstrap admin initialized with username: %s\n", initialUsername)
	}

	// Seed sample Tenants
	var tenantCount int
	db.QueryRow("SELECT COUNT(*) FROM tenants").Scan(&tenantCount)
	if tenantCount == 0 {
		db.Exec(`INSERT INTO tenants (name, slug, tier, sla, seat_limit) VALUES 
			('FintechCorp Global', 'fintechcorp', 'Financial-Grade', '99.99%', 250),
			('HealthSecure Systems', 'healthsecure', 'Enterprise', '99.95%', 100),
			('CloudScale Infrastructure', 'cloudscale', 'Standard', '99.9%', 50)
		`)
	}

	// Seed sample Vendors
	var vendorCount int
	db.QueryRow("SELECT COUNT(*) FROM vendors").Scan(&vendorCount)
	if vendorCount == 0 {
		db.Exec(`INSERT INTO vendors (name, category, criticality, inherent_risk, residual_risk, soc2_certified, iso27001_certified, dpa_signed, next_review_date, notes) VALUES 
			('Amazon Web Services (AWS)', 'Cloud Infrastructure', 'Tier 1', 5, 2, 1, 1, 1, '2027-01-15', 'Primary cloud infrastructure host. SOC 2 Type II and ISO 27001 verified.'),
			('Stripe Payments Inc.', 'Payment Gateway', 'Tier 1', 5, 1, 1, 1, 1, '2026-11-30', 'PCI-DSS Level 1 compliant cardholder data environment.'),
			('Datadog Security & SIEM', 'Observability', 'Tier 2', 4, 2, 1, 1, 1, '2026-12-01', 'Cloud SIEM and APM monitoring cluster.'),
			('Slack Enterprise Grid', 'Collaboration', 'Tier 3', 3, 2, 1, 1, 1, '2027-03-10', 'Encrypted internal SOC communication.')
		`)
	}

	// Seed sample Cloud Resources
	var resourceCount int
	db.QueryRow("SELECT COUNT(*) FROM cloud_resources").Scan(&resourceCount)
	if resourceCount == 0 {
		db.Exec(`INSERT INTO cloud_resources (name, asset_type, environment, sensitivity, owner) VALUES 
			('prod-k8s-cluster-01', 'Kubernetes Cluster', 'Production', 'Confidential', 'DevOps Lead'),
			('customer-postgres-primary', 'PostgreSQL DB', 'Production', 'PCI-DSS', 'Database Admin'),
			('pci-s3-vault', 'S3 Storage Vault', 'Production', 'PCI-DSS', 'Security Team'),
			('fintech-api-gateway', 'API Gateway', 'Production', 'Confidential', 'Platform Eng'),
			('staging-vpc-subnet', 'VPC Subnet', 'Staging', 'Public', 'Infrastructure Team')
		`)
	}
}

func main() {
	secretEnv := os.Getenv("JWT_SECRET")
	if secretEnv != "" {
		jwtSecret = []byte(secretEnv)
	} else {
		jwtSecret = []byte("sentinel_grc_default_dev_key_do_not_use_in_prod")
	}

	initDB()
	defer db.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("IAM Service OK"))
	})

	// Auth
	mux.HandleFunc("/api/auth/login", loginHandler)
	mux.HandleFunc("/api/auth/verify", verifyHandler)
	
	// Users
	mux.HandleFunc("/api/users", usersHandler)
	mux.HandleFunc("/api/users/", userActionHandler)

	// Tenants
	mux.HandleFunc("/api/tenants", tenantsHandler)
	mux.HandleFunc("/api/tenants/", tenantActionHandler)

	// Vendors (TPRM)
	mux.HandleFunc("/api/vendors", vendorsHandler)
	mux.HandleFunc("/api/vendors/", vendorActionHandler)

	// Cloud Resources & JIT PAM
	mux.HandleFunc("/api/resources", resourcesHandler)
	mux.HandleFunc("/api/resources/allocations", allocationsHandler)
	mux.HandleFunc("/api/resources/allocations/", allocationActionHandler)
	mux.HandleFunc("/api/resources/jit", jitRequestsHandler)
	mux.HandleFunc("/api/resources/jit/", jitActionHandler)
	mux.HandleFunc("/api/resources/", resourceActionHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	fmt.Printf("IAM & Enterprise Governance Service starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func isSuspended(suspendedUntil *string) bool {
	if suspendedUntil == nil || *suspendedUntil == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, *suspendedUntil)
	if err != nil {
		return false
	}
	return time.Now().Before(t)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var id int
	var hash, role string
	var suspendedUntil sql.NullString
	err := db.QueryRow("SELECT id, password_hash, role, suspended_until FROM users WHERE username = ?", req.Username).Scan(&id, &hash, &role, &suspendedUntil)
	
	if err != nil {
		http.Error(w, "Unauthorized: Invalid credentials", http.StatusUnauthorized)
		return
	}

	var su *string
	if suspendedUntil.Valid {
		su = &suspendedUntil.String
	}

	if isSuspended(su) {
		http.Error(w, "Forbidden: Account is suspended", http.StatusForbidden)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "Unauthorized: Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username,
		"role": role,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := LoginResponse{Token: "Bearer " + tokenString}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var suspendedUntil sql.NullString
	err := db.QueryRow("SELECT suspended_until FROM users WHERE username = ?", username).Scan(&suspendedUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Unauthorized: User deleted", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	var su *string
	if suspendedUntil.Valid {
		su = &suspendedUntil.String
	}

	if isSuspended(su) {
		http.Error(w, "Forbidden: Account suspended", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, username, role, suspended_until FROM users")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var u User
			var su sql.NullString
			if err := rows.Scan(&u.ID, &u.Username, &u.Role, &su); err != nil {
				continue
			}
			if su.Valid {
				u.SuspendedUntil = &su.String
			}
			users = append(users, u)
		}
		json.NewEncoder(w).Encode(users)
	} else if r.Method == http.MethodPost {
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		_, err := db.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, req.Username, string(hash), req.Role)
		if err != nil {
			http.Error(w, "Username taken or error", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func userActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[3]
	action := ""
	if len(parts) > 4 {
		action = parts[4]
	}

	if r.Method == http.MethodDelete {
		db.Exec("DELETE FROM users WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodPut {
		if action == "suspend" {
			var req SuspendRequest
			json.NewDecoder(r.Body).Decode(&req)
			db.Exec("UPDATE users SET suspended_until = ? WHERE id = ?", req.SuspendedUntil, id)
			w.WriteHeader(http.StatusOK)
			return
		}
		if action == "activate" {
			db.Exec("UPDATE users SET suspended_until = NULL WHERE id = ?", id)
			w.WriteHeader(http.StatusOK)
			return
		}
		if action == "role" {
			var req RoleRequest
			json.NewDecoder(r.Body).Decode(&req)
			db.Exec("UPDATE users SET role = ? WHERE id = ?", req.Role, id)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// ---------------- TENANTS HANDLERS ----------------
func tenantsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, slug, tier, sla, seat_limit, created_at FROM tenants")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var tenants []Tenant
		for rows.Next() {
			var t Tenant
			if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Tier, &t.SLA, &t.SeatLimit, &t.CreatedAt); err != nil {
				continue
			}
			t.ActiveUsers = 12 + t.ID*4
			tenants = append(tenants, t)
		}
		json.NewEncoder(w).Encode(tenants)
	} else if r.Method == http.MethodPost {
		var t Tenant
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		slug := strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
		_, err := db.Exec(`INSERT INTO tenants (name, slug, tier, sla, seat_limit) VALUES (?, ?, ?, ?, ?)`, t.Name, slug, t.Tier, t.SLA, t.SeatLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func tenantActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[3]
	if r.Method == http.MethodDelete {
		db.Exec("DELETE FROM tenants WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// ---------------- VENDORS HANDLERS ----------------
func vendorsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, category, criticality, inherent_risk, residual_risk, soc2_certified, iso27001_certified, dpa_signed, next_review_date, notes FROM vendors")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var vendors []Vendor
		for rows.Next() {
			var v Vendor
			var notes sql.NullString
			if err := rows.Scan(&v.ID, &v.Name, &v.Category, &v.Criticality, &v.InherentRisk, &v.ResidualRisk, &v.SOC2Certified, &v.ISO27001Certified, &v.DPASigned, &v.NextReviewDate, &notes); err != nil {
				continue
			}
			if notes.Valid {
				v.Notes = notes.String
			}
			vendors = append(vendors, v)
		}
		json.NewEncoder(w).Encode(vendors)
	} else if r.Method == http.MethodPost {
		var v Vendor
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`INSERT INTO vendors (name, category, criticality, inherent_risk, residual_risk, soc2_certified, iso27001_certified, dpa_signed, next_review_date, notes) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.Name, v.Category, v.Criticality, v.InherentRisk, v.ResidualRisk, v.SOC2Certified, v.ISO27001Certified, v.DPASigned, v.NextReviewDate, v.Notes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func vendorActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[3]
	if r.Method == http.MethodDelete {
		db.Exec("DELETE FROM vendors WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// ---------------- CLOUD RESOURCES & JIT PAM HANDLERS ----------------
func resourcesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, asset_type, environment, sensitivity, owner FROM cloud_resources")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var resources []CloudResource
		for rows.Next() {
			var cr CloudResource
			if err := rows.Scan(&cr.ID, &cr.Name, &cr.AssetType, &cr.Environment, &cr.Sensitivity, &cr.Owner); err != nil {
				continue
			}
			resources = append(resources, cr)
		}
		json.NewEncoder(w).Encode(resources)
	} else if r.Method == http.MethodPost {
		var cr CloudResource
		if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`INSERT INTO cloud_resources (name, asset_type, environment, sensitivity, owner) VALUES (?, ?, ?, ?, ?)`,
			cr.Name, cr.AssetType, cr.Environment, cr.Sensitivity, cr.Owner)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func allocationsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query(`
			SELECT ra.id, ra.user_id, u.username, ra.resource_id, cr.name, ra.permission, ra.granted_at
			FROM resource_allocations ra
			JOIN users u ON ra.user_id = u.id
			JOIN cloud_resources cr ON ra.resource_id = cr.id
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		allocs := make([]ResourceAllocation, 0)
		for rows.Next() {
			var a ResourceAllocation
			if err := rows.Scan(&a.ID, &a.UserID, &a.Username, &a.ResourceID, &a.ResourceName, &a.Permission, &a.GrantedAt); err != nil {
				continue
			}
			allocs = append(allocs, a)
		}
		json.NewEncoder(w).Encode(allocs)
	} else if r.Method == http.MethodPost {
		var a ResourceAllocation
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`INSERT OR REPLACE INTO resource_allocations (user_id, resource_id, permission) VALUES (?, ?, ?)`,
			a.UserID, a.ResourceID, a.Permission)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func jitRequestsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		rows, err := db.Query(`
			SELECT j.id, j.user_id, u.username, j.resource_id, cr.name, j.requested_role, j.justification, j.ticket_ref, j.ttl_minutes, j.status, j.expires_at, j.approved_by, j.created_at
			FROM jit_requests j
			JOIN users u ON j.user_id = u.id
			JOIN cloud_resources cr ON j.resource_id = cr.id
			ORDER BY j.id DESC
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		list := make([]JITRequest, 0)
		for rows.Next() {
			var j JITRequest
			var exp, appBy sql.NullString
			if err := rows.Scan(&j.ID, &j.UserID, &j.Username, &j.ResourceID, &j.ResourceName, &j.RequestedRole, &j.Justification, &j.TicketRef, &j.TTLMinutes, &j.Status, &exp, &appBy, &j.CreatedAt); err != nil {
				continue
			}
			if exp.Valid {
				j.ExpiresAt = &exp.String
			}
			if appBy.Valid {
				j.ApprovedBy = &appBy.String
			}
			list = append(list, j)
		}
		json.NewEncoder(w).Encode(list)
	} else if r.Method == http.MethodPost {
		var j JITRequest
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`INSERT INTO jit_requests (user_id, resource_id, requested_role, justification, ticket_ref, ttl_minutes, status) VALUES (?, ?, ?, ?, ?, ?, 'PENDING')`,
			j.UserID, j.ResourceID, j.RequestedRole, j.Justification, j.TicketRef, j.TTLMinutes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func jitActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[4]
	action := ""
	if len(parts) > 5 {
		action = parts[5]
	}

	approver := r.Header.Get("X-User-Name")
	if approver == "" {
		approver = "manager"
	}

	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		if action == "approve" {
			var ttlMinutes int
			db.QueryRow("SELECT ttl_minutes FROM jit_requests WHERE id = ?", id).Scan(&ttlMinutes)
			if ttlMinutes == 0 {
				ttlMinutes = 60
			}
			expiresAt := time.Now().Add(time.Duration(ttlMinutes) * time.Minute).Format(time.RFC3339)
			db.Exec("UPDATE jit_requests SET status = 'APPROVED', approved_by = ?, expires_at = ? WHERE id = ?", approver, expiresAt, id)
			w.WriteHeader(http.StatusOK)
			return
		}
		if action == "reject" {
			db.Exec("UPDATE jit_requests SET status = 'REJECTED', approved_by = ? WHERE id = ?", approver, id)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func resourceActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[3]
	if r.Method == http.MethodDelete {
		db.Exec("DELETE FROM resource_allocations WHERE resource_id = ?", id)
		db.Exec("DELETE FROM jit_requests WHERE resource_id = ?", id)
		db.Exec("DELETE FROM cloud_resources WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func allocationActionHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id := parts[4]
	if r.Method == http.MethodDelete {
		db.Exec("DELETE FROM resource_allocations WHERE id = ?", id)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

