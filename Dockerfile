# Vulnex on Render: .NET API + built React UI + the Python engine (scanner, enrichment).
#
#   stage 1  build the React app
#   stage 2  publish the .NET API
#   stage 3  runtime: ASP.NET image with Python for the engine bridge and Alembic migrations

FROM node:22-slim AS web
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS api
WORKDIR /src/api
COPY api/Vulnex.Api/Vulnex.Api.csproj Vulnex.Api/
RUN dotnet restore Vulnex.Api/Vulnex.Api.csproj
COPY api/Vulnex.Api/ Vulnex.Api/
RUN dotnet publish Vulnex.Api/Vulnex.Api.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip python3-venv git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend/ /app/backend/
COPY data/ /app/data/
COPY --from=api /out/ /app/api/
COPY --from=web /src/frontend/dist/ /app/frontend/dist/
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENV VULNEX_PYTHON=/opt/venv/bin/python \
    VULNEX_BACKEND_DIR=/app/backend \
    VULNEX_FRONTEND_DIR=/app/frontend/dist \
    DOTNET_gcServer=0 \
    ASPNETCORE_ENVIRONMENT=Production
EXPOSE 10000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
