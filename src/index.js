const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const server = require('./server');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Conectar ao MongoDB
mongoose.connect('mongodb://localhost:27017/lis', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {})
.catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Usar as rotas do servidor
app.use(server);

// Iniciar o servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  // Server started successfully
}); 