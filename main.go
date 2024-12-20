package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id" bson:"_id,omitempty"`
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Role     string `json:"role" bson:"role"`
}

type Course struct {
    ID        string    `json:"id" bson:"_id,omitempty"`
    Title     string    `json:"title" bson:"title"`
    Teacher   string    `json:"teacher" bson:"teacher"` // Stores the teacher's username
    Duration  string    `json:"duration" bson:"duration"`
    Enrolled  []string  `json:"enrolled" bson:"enrolled"` // List of enrolled student usernames
    CreatedAt time.Time `json:"created_at" bson:"created_at"`
}



type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	jwtKey         = []byte("secret_key")
	databaseClient *mongo.Client
	dbName         = "school"
	userCollection = "users"
	courseCollection = "courses"
)

func connectDB() {
	var err error
	clientOptions := options.Client().ApplyURI("mongodb+srv://amadiar654:Lnb0PBPuGbYFApXm@cluster0.6gzdz.mongodb.net/")
	databaseClient, err = mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	log.Println("Connected to MongoDB")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func generateJWT(username, role string) (string, error) {
    claims := &jwt.StandardClaims{
        Subject:   username,       // Username
        ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
        Issuer:    role,           // Role (e.g., "teacher" or "student")
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}


func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if user.Role != "teacher" && user.Role != "student" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = hashedPassword

	collection := databaseClient.Database(dbName).Collection(userCollection)
	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var loginReq LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    collection := databaseClient.Database(dbName).Collection(userCollection)
    var user User
    err := collection.FindOne(context.Background(), bson.M{"username": loginReq.Username}).Decode(&user)
    if err != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    if !checkPasswordHash(loginReq.Password, user.Password) {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Pass the user's role to the token
    token, err := generateJWT(user.Username, user.Role)
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"token": token})
}


// Middleware to check if the user is a teacher based on the JWT role
func isTeacherMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Remove the "Bearer " prefix from the token string
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the user role is teacher
		if claims.Issuer != "teacher" {
			http.Error(w, "Unauthorized: Only teachers can create courses", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func createCourseHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JWT token to get the teacher's username
    tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims := &jwt.StandardClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    if claims.Issuer != "teacher" {
        http.Error(w, "Unauthorized: Only teachers can create courses", http.StatusForbidden)
        return
    }

    // Decode the course information
    var course Course
    if err := json.NewDecoder(r.Body).Decode(&course); err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    // Add teacher's username and timestamp to the course
    course.Teacher = claims.Subject // Use the username from the token
    course.CreatedAt = time.Now()

    // Save the course to the database
    collection := databaseClient.Database(dbName).Collection(courseCollection)
    _, err = collection.InsertOne(context.Background(), course)
    if err != nil {
        http.Error(w, "Failed to create course", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "Course created successfully"})
}

func updateCourseHandler(w http.ResponseWriter, r *http.Request) {
	// Parse JWT token to get the teacher's username
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if claims.Issuer != "teacher" {
		http.Error(w, "Unauthorized: Only teachers can update courses", http.StatusForbidden)
		return
	}

	// Get the course ID from the URL
	vars := mux.Vars(r)
	courseID := vars["id"]

	// Convert courseID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Decode the course information
	var updatedCourse Course
	if err := json.NewDecoder(r.Body).Decode(&updatedCourse); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Set the teacher's username to ensure the teacher can only update their courses
	filter := bson.M{"_id": objectID, "teacher": claims.Subject}
	update := bson.M{"$set": bson.M{
		"title":    updatedCourse.Title,
		"duration": updatedCourse.Duration,
	}}

	collection := databaseClient.Database(dbName).Collection(courseCollection)
	result, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		http.Error(w, "Failed to update course", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		http.Error(w, "Course not found or not authorized", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Course updated successfully"})
}


func deleteCourseHandler(w http.ResponseWriter, r *http.Request) {
	// Parse JWT token to get the teacher's username
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if claims.Issuer != "teacher" {
		http.Error(w, "Unauthorized: Only teachers can delete courses", http.StatusForbidden)
		return
	}

	// Get the course ID from the URL parameters
	vars := mux.Vars(r)
	courseID := vars["id"]

	// Convert courseID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Delete the course from the database
	collection := databaseClient.Database(dbName).Collection(courseCollection)
	filter := bson.M{"_id": objectID, "teacher": claims.Subject}
	result, err := collection.DeleteOne(context.Background(), filter)
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Failed to delete course or course not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Course deleted successfully"})
}

func enrollInCourseHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JWT token to get the user's role and username
    tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims := &jwt.StandardClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Ensure the user is a student
    if claims.Issuer != "student" {
        http.Error(w, "Unauthorized: Only students can enroll", http.StatusForbidden)
        return
    }

    // Get the student's username from the token
    studentUsername := claims.Subject

    // Get the course ID from URL parameters
    courseID := mux.Vars(r)["course_id"]

    // Log the courseID to debug
    fmt.Println("Attempting to enroll in course with ID:", courseID)

    // Convert courseID to ObjectId (if it's stored as an ObjectId in the database)
    objID, err := primitive.ObjectIDFromHex(courseID)
    if err != nil {
        http.Error(w, "Invalid course ID format", http.StatusBadRequest)
        return
    }

    // Find the course by ObjectId
    collection := databaseClient.Database(dbName).Collection(courseCollection)
    var course Course
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&course)
    if err != nil {
        fmt.Println("Error finding course:", err)  // Log the actual error from the database
        http.Error(w, "Course not found", http.StatusNotFound)
        return
    }

    // Log the course data to check if it was found
    fmt.Println("Course found:", course)

    // Check if the student is already enrolled
    for _, enrolled := range course.Enrolled {
        if enrolled == studentUsername {
            http.Error(w, "Student already enrolled", http.StatusConflict)
            return
        }
    }

    // Add the student to the enrolled list
    course.Enrolled = append(course.Enrolled, studentUsername)

    // Update the course in the database
    _, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, bson.M{
        "$set": bson.M{"enrolled": course.Enrolled},
    })
    if err != nil {
        http.Error(w, "Failed to enroll in course", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Student enrolled successfully"})
}


func unenrollFromCourseHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JWT token to get the user's role and username
    tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims := &jwt.StandardClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Ensure the user is a student
    if claims.Issuer != "student" {
        http.Error(w, "Unauthorized: Only students can unenroll", http.StatusForbidden)
        return
    }

    // Get the student's username from the token
    studentUsername := claims.Subject

    // Get the course ID from URL parameters
    courseID := mux.Vars(r)["course_id"]

    // Log the courseID to debug
    fmt.Println("Attempting to unenroll from course with ID:", courseID)

    // Convert courseID to ObjectId (if it's stored as an ObjectId in the database)
    objID, err := primitive.ObjectIDFromHex(courseID)
    if err != nil {
        http.Error(w, "Invalid course ID format", http.StatusBadRequest)
        return
    }

    // Find the course by ObjectId
    collection := databaseClient.Database(dbName).Collection(courseCollection)
    var course Course
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&course)
    if err != nil {
        fmt.Println("Error finding course:", err)  // Log the actual error from the database
        http.Error(w, "Course not found", http.StatusNotFound)
        return
    }

    // Log the course data to check if it was found
    fmt.Println("Course found:", course)

    // Check if the student is enrolled in the course
    var updatedEnrolled []string
    enrolled := false
    for _, enrolledStudent := range course.Enrolled {
        if enrolledStudent == studentUsername {
            enrolled = true
        } else {
            updatedEnrolled = append(updatedEnrolled, enrolledStudent)
        }
    }

    if !enrolled {
        http.Error(w, "Student not enrolled in this course", http.StatusBadRequest)
        return
    }

    // Update the course by removing the student from the enrolled list
    _, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, bson.M{
        "$set": bson.M{"enrolled": updatedEnrolled},
    })
    if err != nil {
        http.Error(w, "Failed to unenroll from course", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Student unenrolled successfully"})
}


func getEnrolledStudentsHandler(w http.ResponseWriter, r *http.Request) {
    // Parse JWT token to get the user's role and username
    tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims := &jwt.StandardClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Ensure the user is a teacher
    if claims.Issuer != "teacher" {
        http.Error(w, "Unauthorized: Only teachers can view enrolled students", http.StatusForbidden)
        return
    }

    // Get the teacher's username from the token
    teacherUsername := claims.Subject

    // Get the course ID from URL parameters
    courseID := mux.Vars(r)["course_id"]

    // Log the courseID to debug
    fmt.Println("Teacher attempting to view students in course with ID:", courseID)

    // Convert courseID to ObjectId (if it's stored as an ObjectId in the database)
    objID, err := primitive.ObjectIDFromHex(courseID)
    if err != nil {
        http.Error(w, "Invalid course ID format", http.StatusBadRequest)
        return
    }

    // Find the course by ObjectId
    collection := databaseClient.Database(dbName).Collection(courseCollection)
    var course Course
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&course)
    if err != nil {
        fmt.Println("Error finding course:", err)  // Log the actual error from the database
        http.Error(w, "Course not found", http.StatusNotFound)
        return
    }

    // Check if the logged-in teacher is the one who created the course
    if course.Teacher != teacherUsername {
        http.Error(w, "Unauthorized: You are not the teacher of this course", http.StatusForbidden)
        return
    }

    // Return the list of enrolled students
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "course_id": courseID,
        "enrolled_students": course.Enrolled,
    })
}




func main() {
	connectDB()
	defer func() {
		if err := databaseClient.Disconnect(context.Background()); err != nil {
			log.Fatalf("Failed to disconnect MongoDB: %v", err)
		}
	}()

	r := mux.NewRouter()

	// User authentication routes
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Course-related routes
	r.Handle("/courses", isTeacherMiddleware(http.HandlerFunc(createCourseHandler))).Methods("POST")
	r.Handle("/courses/{id}", isTeacherMiddleware(http.HandlerFunc(updateCourseHandler))).Methods("PUT")
	r.Handle("/courses/{id}", isTeacherMiddleware(http.HandlerFunc(deleteCourseHandler))).Methods("DELETE")

	r.HandleFunc("/course/{course_id}/enroll", enrollInCourseHandler).Methods("POST")
r.HandleFunc("/course/{course_id}/unenroll", unenrollFromCourseHandler).Methods("POST")

r.HandleFunc("/course/{course_id}/students", getEnrolledStudentsHandler).Methods("GET")



	log.Println("Server is running on port 8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

