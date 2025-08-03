# 🐳 Docker Setup - Backend LIS MODAS

Este documento explica como containerizar e executar o backend LIS MODAS usando Docker.

## 📋 Pré-requisitos

- Docker instalado
- Docker Compose instalado
- Node.js 18+ (para desenvolvimento local)

## 🚀 Deploy Rápido

### 1. Configurar Variáveis de Ambiente

```bash
# Copiar arquivo de exemplo
cp env.example .env

# Editar o arquivo .env com suas configurações
nano .env
```

### 2. Executar Deploy Automático

```bash
# Dar permissão de execução ao script
chmod +x deploy.sh

# Executar deploy
./deploy.sh
```

## 🔧 Deploy Manual

### 1. Construir a Imagem

```bash
docker build -t lismodas-backend .
```

### 2. Executar com Docker Compose

```bash
# Iniciar containers
docker-compose up -d

# Ver logs
docker-compose logs -f backend

# Parar containers
docker-compose down
```

## 📁 Estrutura de Arquivos

```
Backend-Lis/
├── Dockerfile              # Configuração do container
├── docker-compose.yml      # Orquestração dos serviços
├── .dockerignore          # Arquivos ignorados no build
├── deploy.sh              # Script de deploy automático
├── env.example            # Exemplo de variáveis de ambiente
├── src/                   # Código fonte
└── uploads/               # Diretório de uploads (volume)
```

## ⚙️ Configurações

### Variáveis de Ambiente (.env)

```env
# Servidor
NODE_ENV=production
PORT=3001

# MongoDB
MONGODB_URI=mongodb://localhost:27017/lismodas

# JWT
JWT_SECRET=your_super_secret_jwt_key_here

# AWS S3
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your_s3_bucket_name
```

### Portas

- **Backend**: 3001
- **MongoDB** (opcional): 27017

## 🐳 Comandos Docker Úteis

```bash
# Ver containers em execução
docker ps

# Ver logs em tempo real
docker-compose logs -f backend

# Entrar no container
docker exec -it lismodas-backend sh

# Reiniciar container
docker-compose restart backend

# Ver uso de recursos
docker stats

# Limpar recursos não utilizados
docker system prune -a
```

## 🔍 Troubleshooting

### Container não inicia

```bash
# Verificar logs
docker-compose logs backend

# Verificar se as variáveis de ambiente estão corretas
docker exec -it lismodas-backend env
```

### Problemas de conectividade

```bash
# Verificar se a porta está sendo usada
netstat -tulpn | grep 3001

# Verificar rede Docker
docker network ls
docker network inspect lismodas_lismodas-network
```

### Problemas de permissão

```bash
# Dar permissão ao diretório uploads
chmod 755 uploads/

# Verificar permissões no container
docker exec -it lismodas-backend ls -la uploads/
```

## 🚀 Produção

### Usando MongoDB Atlas (Recomendado)

1. Configure `MONGODB_URI` com sua string de conexão do MongoDB Atlas
2. Execute o deploy normalmente

### Usando MongoDB Local

1. Descomente a seção MongoDB no `docker-compose.yml`
2. Configure `MONGODB_URI=mongodb://admin:password@mongodb:27017/lismodas`

### SSL/HTTPS

Para produção com HTTPS, considere usar um proxy reverso como Nginx ou Traefik.

## 📊 Monitoramento

### Health Check

O backend expõe endpoints de health check:

```bash
# Verificar status
curl http://localhost:3001/health

# Verificar versão
curl http://localhost:3001/version
```

### Logs

```bash
# Logs em tempo real
docker-compose logs -f backend

# Logs com timestamp
docker-compose logs -t backend

# Últimas 100 linhas
docker-compose logs --tail=100 backend
```

## 🔄 Atualizações

### Atualizar Código

```bash
# Parar containers
docker-compose down

# Reconstruir com novo código
docker-compose up --build -d

# Verificar logs
docker-compose logs -f backend
```

### Atualizar Variáveis de Ambiente

```bash
# Editar .env
nano .env

# Reiniciar container
docker-compose restart backend
```

## 🛡️ Segurança

### Boas Práticas

1. **Nunca commite o arquivo `.env`**
2. **Use secrets do Docker** para senhas em produção
3. **Configure firewall** para limitar acesso às portas
4. **Use HTTPS** em produção
5. **Monitore logs** regularmente

### Exemplo de Secrets

```yaml
# docker-compose.yml
services:
  backend:
    secrets:
      - jwt_secret
      - mongodb_uri

secrets:
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  mongodb_uri:
    file: ./secrets/mongodb_uri.txt
```

## 📞 Suporte

Para problemas específicos do Docker:

1. Verifique os logs: `docker-compose logs backend`
2. Verifique a conectividade: `docker network inspect lismodas_lismodas-network`
3. Verifique recursos: `docker stats`
4. Consulte a documentação oficial do Docker

---

**🎉 Seu backend LIS MODAS está agora containerizado e pronto para produção!** 