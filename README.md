# Golang - CRUD API

This repository serves as a learning platform for Go programming language, specifically focused on building a CRUD API with PostgreSQL database integration.

## Project Overview

The project implements a RESTful API for managing a simple resource (users) with complete CRUD operations.

### Key Features

- RESTful API implementation
- PostgreSQL database integration using GORM
- JWT-based authentication
- Rate limiting
- Structured logging
- Automated testing
- Docker support for local development
- Swagger/OpenAPI documentation

## Prerequisites

- Go 1.24.1 or higher
- Docker and Docker Compose
- PostgreSQL (will be run in Docker)

## Getting Started

1. Clone the repository
```bash
git clone https://github.com/petarzarkov/golang-api.git goapi
cd goapi
```

2. Install dependencies
```bash
go mod download
```

3. Run the application
```bash
go run cmd/api/main.go
```

## Development

### Running Tests
```bash
go test ./...
```

### Building the Application
```bash
go build -o bin/api cmd/api/main.go
```

### API Documentation
- Swagger docs here: http://localhost:8080/api
