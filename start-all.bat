@echo off
echo Starting Eureka Server...
start cmd /k "cd infrastructure\eureka-server && mvn spring-boot:run"
timeout /t 10

echo Starting Config Server...
start cmd /k "cd infrastructure\config-server && mvn spring-boot:run"
timeout /t 5

echo Starting API Gateway...
start cmd /k "cd infrastructure\api-gateway && mvn spring-boot:run"

echo Starting Services...
start cmd /k "cd microservices\user-service && mvn spring-boot:run"
start cmd /k "cd microservices\vault-service && mvn spring-boot:run"
start cmd /k "cd microservices\generator-service && mvn spring-boot:run"
start cmd /k "cd microservices\security-service && mvn spring-boot:run"
start cmd /k "cd microservices\notification-service && mvn spring-boot:run"

echo All services are starting up!
