#!/bin/bash

# Script de deploy para o backend LIS MODAS
echo "🚀 Iniciando deploy do Backend LIS MODAS..."

# Verificar se o Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "❌ Docker não está instalado. Por favor, instale o Docker primeiro."
    exit 1
fi

# Verificar se o Docker Compose está instalado
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose não está instalado. Por favor, instale o Docker Compose primeiro."
    exit 1
fi

# Verificar se o arquivo .env existe
if [ ! -f .env ]; then
    echo "⚠️  Arquivo .env não encontrado!"
    echo "📝 Copiando arquivo de exemplo..."
    cp env.example .env
    echo "✅ Arquivo .env criado. Por favor, configure as variáveis de ambiente antes de continuar."
    echo "🔧 Edite o arquivo .env com suas configurações e execute novamente este script."
    exit 1
fi

# Parar containers existentes
echo "🛑 Parando containers existentes..."
docker-compose down

# Remover imagens antigas (opcional)
read -p "🗑️  Deseja remover imagens antigas? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🧹 Removendo imagens antigas..."
    docker system prune -f
fi

# Construir e iniciar containers
echo "🔨 Construindo e iniciando containers..."
docker-compose up --build -d

# Verificar status dos containers
echo "📊 Verificando status dos containers..."
docker-compose ps

# Mostrar logs
echo "📋 Logs do container:"
docker-compose logs -f --tail=50 backend

echo "✅ Deploy concluído!"
echo "🌐 Backend disponível em: http://localhost:3001"
echo "📝 Para ver logs em tempo real: docker-compose logs -f backend"
echo "🛑 Para parar: docker-compose down" 