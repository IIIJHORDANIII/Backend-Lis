require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const User = require('./models/User');
const Product = require('./models/Product');
const CustomList = require('./models/CustomList');
const Sale = require('./models/Sale');
const Condicional = require('./models/Condicional');
const { uploadToS3, deleteFromS3 } = require('./services/s3Service');
const bcrypt = require('bcryptjs');
const DraftSale = require('./models/DraftSale');
const router = express.Router();
const config = require('./config/config');
const { cleanupS3Images } = require('./scripts/cleanupS3');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ["http://localhost:3005", "http://localhost:8081", "https://www.lismodas.com.br"],
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [,
      "http://localhost:3005",
      "http://localhost:8081", 
      "https://www.lismodas.com.br"
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = ["http://localhost:3000", "http://localhost:3001", "http://localhost:3005", "https://frontend-lis.vercel.app", "https://www.jhorello.com.br"];
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all origins for mobile development
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Rota de teste simples
app.get('/api/test-simple', (req, res) => {
  res.json({ message: 'Teste simples funcionando!', timestamp: new Date().toISOString() });
});

// Rota para verificar status dos produtos
app.get('/api/debug/stock-status', async (req, res) => {
  try {
    console.log('🔍 Verificando produtos...');
    
    const products = await Product.find().select('name quantity').limit(10);
    const totalProducts = await Product.countDocuments();
    const productsWithStock = await Product.countDocuments({ quantity: { $gt: 0 } });
    const productsOutOfStock = await Product.countDocuments({ quantity: { $lte: 0 } });
    
    console.log('✅ Produtos verificados:', { totalProducts, productsWithStock, productsOutOfStock });
    
    res.json({ 
      products,
      summary: {
        total: totalProducts,
        withStock: productsWithStock,
        outOfStock: productsOutOfStock
      }
    });
  } catch (error) {
    console.error('❌ Erro ao verificar produtos:', error);
    res.status(500).json({ error: error.message });
  }
});

// Rota para debug específico da lista
app.get('/api/debug/list/:listId', async (req, res) => {
  try {
    const { listId } = req.params;
    console.log(`🔍 Verificando lista: ${listId}`);
    
    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'Lista não encontrada' });
    }
    
    const sales = await Sale.find({ listId: listId });
    const closedSales = await Sale.find({ listId: listId, status: 'closed' });
    
    res.json({
      list: {
        _id: list._id,
        name: list.name,
        status: list.status,
        userId: list.userId,
        products: list.products
      },
      sales: {
        total: sales.length,
        closed: closedSales.length,
        active: sales.length - closedSales.length
      },
      salesDetails: sales.map(sale => ({
        _id: sale._id,
        status: sale.status,
        total: sale.total,
        createdAt: sale.createdAt
      }))
    });
  } catch (error) {
    console.error('❌ Erro ao verificar lista:', error);
    res.status(500).json({ error: error.message });
  }
});

// Rota para debug das vendas
app.get('/api/debug/sales', async (req, res) => {
  try {
    console.log('🔍 Verificando vendas...');
    
    const allSales = await Sale.find().limit(10);
    const salesWithListId = await Sale.find({ listId: { $exists: true, $ne: null } });
    const salesWithoutListId = await Sale.find({ listId: { $exists: false } });
    const closedSales = await Sale.find({ status: 'closed' });
    
    // Verificar usuários únicos com vendas
    const uniqueUserIds = [...new Set(allSales.map(sale => sale.userId.toString()))];
    const listsByUser = {};
    
    for (const userId of uniqueUserIds) {
      const userLists = await CustomList.find({ userId: userId });
      listsByUser[userId] = userLists.length;
    }
    
    res.json({
      summary: {
        total: allSales.length,
        withListId: salesWithListId.length,
        withoutListId: salesWithoutListId.length,
        closed: closedSales.length,
        uniqueUsers: uniqueUserIds.length
      },
      users: uniqueUserIds,
      listsByUser,
      sampleSales: allSales.map(sale => ({
        _id: sale._id,
        userId: sale.userId,
        listId: sale.listId,
        status: sale.status,
        total: sale.total,
        createdAt: sale.createdAt
      }))
    });
  } catch (error) {
    console.error('❌ Erro ao verificar vendas:', error);
    res.status(500).json({ error: error.message });
  }
});

// Rota para debug das listas
app.get('/api/debug/lists', async (req, res) => {
  try {
    console.log('🔍 Verificando listas...');
    
    const allLists = await CustomList.find();
    const activeLists = await CustomList.find({ status: 'active' });
    const closedLists = await CustomList.find({ status: 'closed' });
    
    res.json({
      summary: {
        total: allLists.length,
        active: activeLists.length,
        closed: closedLists.length
      },
      lists: allLists.map(list => ({
        _id: list._id,
        name: list.name,
        status: list.status,
        userId: list.userId,
        productsCount: list.products.length
      }))
    });
  } catch (error) {
    console.error('❌ Erro ao verificar listas:', error);
    res.status(500).json({ error: error.message });
  }
});

// Rota temporária para verificar status dos produtos e listas (sem autenticação para debug)
app.get('/api/debug/status', async (req, res) => {
  try {
    console.log('🔍 Verificando status do sistema...');

    // Contar produtos
    const productsCount = await Product.countDocuments();
    const productsWithStock = await Product.countDocuments({ quantity: { $gt: 0 } });
    const productsOutOfStock = await Product.countDocuments({ quantity: { $lte: 0 } });

    // Contar listas custom
    const customListsCount = await CustomList.countDocuments();
    const activeListsCount = await CustomList.countDocuments({ status: 'active' });
    const closedListsCount = await CustomList.countDocuments({ status: 'closed' });

    // Contar vendas
    const salesCount = await Sale.countDocuments();
    const activeSalesCount = await Sale.countDocuments({ status: 'active' });
    const closedSalesCount = await Sale.countDocuments({ status: 'closed' });

    // Buscar alguns produtos para exemplo
    const sampleProducts = await Product.find().limit(5).select('name quantity');

    // Buscar algumas listas para exemplo
    const sampleLists = await CustomList.find().limit(3).select('name status products');

    console.log('✅ Status verificado com sucesso');

    res.json({
      products: {
        total: productsCount,
        withStock: productsWithStock,
        outOfStock: productsOutOfStock,
        sample: sampleProducts
      },
      customLists: {
        total: customListsCount,
        active: activeListsCount,
        closed: closedListsCount,
        sample: sampleLists
      },
      sales: {
        total: salesCount,
        active: activeSalesCount,
        closed: closedSalesCount
      }
    });
  } catch (error) {
    console.error('❌ Erro ao verificar status:', error);
    res.status(500).json({ message: 'Erro ao verificar status', error: error.message });
  }
});

// Middleware para redirecionar rotas sem /api para rotas com /api
app.use((req, res, next) => {
  // Se a rota não começa com /api e não é /uploads ou /, redirecionar
  if (!req.path.startsWith('/api') && !req.path.startsWith('/uploads') && req.path !== '/' && req.path !== '/health' && req.path !== '/version') {
    // Criar nova URL com /api prefix
    const newPath = `/api${req.path}`;
    console.log(`🔄 Redirecting ${req.method} ${req.path} to ${newPath}`);
    req.url = newPath;
  }
  next();
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 15 * 1024 * 1024, // 15MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Check file type
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ Connected to MongoDB Atlas successfully');
  console.log('MongoDB URI:', process.env.MONGODB_URI ? 'Set' : 'Not set');
}).catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  console.error('MongoDB URI:', process.env.MONGODB_URI ? 'Set' : 'Not set');
});

// Socket.IO authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = decoded;
    next();
  });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  // User connected

  socket.on('disconnect', () => {
    // User disconnected
  });
});

// Middleware to authenticate and attach user to req
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    
    // Find user in database
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Attach user to request
    req.user = {
      _id: user._id,
      email: user.email,
      isAdmin: user.isAdmin
    };

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, cpf, password } = req.body;
    const userData = { name, email, password };
    if (cpf) {
      userData.cpf = cpf;
    }
    const user = new User(userData);
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('Login attempt received:', { email: req.body.email });
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    console.log('Searching for user with email:', email);
    const user = await User.findOne({ email });
    
    if (!user) {
      console.log('User not found for email:', email);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    console.log('User found, comparing passwords');
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      console.log('Password mismatch for user:', email);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    console.log('Password match, generating token');
    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    console.log('Login successful for user:', email);
    res.json({
      token,
      user: {
        _id: user._id,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error details:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ message: 'Error during login', details: error.message });
  }
});

// Product routes
app.post('/api/products', authenticate, upload.single('image'), async (req, res) => {
  try {
    const { name, description, costPrice, quantity, category } = req.body;
    
    // Validate required fields
    if (!name || !description || !costPrice) {
      return res.status(400).json({ error: 'Name, description, and cost price are required' });
    }
    
    // Validate costPrice is a valid number
    const costPriceValue = parseFloat(costPrice);
    if (isNaN(costPriceValue) || costPriceValue <= 0) {
      return res.status(400).json({ error: 'Cost price must be a valid number greater than zero' });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'Image is required' });
    }

    // Upload image to S3
    const imageUrl = await uploadToS3(req.file);

    const product = new Product({
      name,
      description,
      costPrice: costPriceValue,
      quantity: parseInt(quantity) || 0,
      category: category || 'masculino', // Default category
      image: imageUrl // Store S3 URL directly
    });
    
    await product.save();
    
    io.emit('productCreated', product);
    res.status(201).json(product);
  } catch (error) {
    console.error('Error creating product:', error);
    
    // Handle specific error types
    if (error.message === 'Only image files are allowed') {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }
    
    if (error.message === 'File too large') {
      return res.status(400).json({ error: 'File size must be less than 15MB' });
    }
    
    if (error.message === 'Failed to upload image to S3') {
      return res.status(500).json({ error: 'Failed to upload image. Please try again.' });
    }
    
    res.status(400).json({ error: error.message });
  }
});

// Add PUT route for updating products
app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, costPrice, quantity, category } = req.body;

    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Update product fields
    product.name = name;
    product.description = description;
    product.costPrice = parseFloat(costPrice);
    product.quantity = parseInt(quantity) || 0;
    if (category) {
      product.category = category;
    }

    await product.save();

    res.json(product);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(400).json({ error: error.message });
  }
});

// Add PUT route for updating products with image
app.put('/api/products/:id/with-image', authenticate, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, costPrice, quantity, category } = req.body;

    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // If a new image is uploaded, delete the old one from S3
    if (req.file) {
      // Delete old image from S3
      await deleteFromS3(product.image);
      
      // Upload new image to S3 (já processada para 9:16)
      const imageUrl = await uploadToS3(req.file);
      product.image = imageUrl;
    }

    // Update product fields
    product.name = name;
    product.description = description;
    product.costPrice = parseFloat(costPrice);
    product.quantity = parseInt(quantity) || 0;
    if (category) {
      product.category = category;
    }

    await product.save();

    res.json(product);
  } catch (error) {
    console.error('Error updating product with image:', error);
    
    // Handle specific error types
    if (error.message === 'Only image files are allowed') {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }
    
    if (error.message === 'File too large') {
      return res.status(400).json({ error: 'File size must be less than 15MB' });
    }
    
    if (error.message === 'Failed to upload image to S3') {
      return res.status(500).json({ error: 'Failed to upload image. Please try again.' });
    }
    
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/products', authenticate, async (req, res) => {
  try {
    
    if (req.user.isAdmin) {
      // Admins can see all products with reserved stock information
      const products = await Product.find();
      
      // Calcular estoque reservado em listas customizadas
      const customLists = await CustomList.find();
      
      // Calcular estoque reservado por produto
      const reservedStockByProduct = new Map();
      for (const list of customLists) {
        for (const item of list.products) {
          const productId = item.productId.toString();
          const reservedQty = item.quantity || 0;
          
          if (reservedStockByProduct.has(productId)) {
            reservedStockByProduct.set(productId, reservedStockByProduct.get(productId) + reservedQty);
          } else {
            reservedStockByProduct.set(productId, reservedQty);
          }
        }
      }
      
      // Adicionar informações de estoque reservado aos produtos
      const productsWithReservedStock = products.map(product => {
        const productId = product._id.toString();
        const reservedStock = reservedStockByProduct.get(productId) || 0;
        const availableStock = Math.max(0, (product.quantity || 0) - reservedStock);
        const isFullyReserved = reservedStock >= (product.quantity || 0);
        
        return {
          ...product.toObject(),
          reservedStock,
          availableStock,
          isFullyReserved
        };
      });
      
      return res.json(productsWithReservedStock);
    }

    // For regular users, only show products in their lists
    const userLists = await CustomList.find({
      $or: [
        { creator: req.user._id },
        { sharedWith: req.user._id },
        { isPublic: true }
      ]
    }).populate('products');

    // Extract unique products from all lists
    const productIds = new Set();
    userLists.forEach(list => {
      list.products.forEach(product => {
        productIds.add(product._id.toString());
      });
    });

    const products = await Product.find({
      _id: { $in: Array.from(productIds) }
    });

    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(400).json({ error: error.message });
  }
});

// Debug endpoint to check product data
app.get('/api/debug/products', async (req, res) => {
  try {
    const products = await Product.find();
    const productData = products.map(product => ({
      id: product._id,
      name: product.name,
      image: product.image,
      createdAt: product.createdAt
    }));
    res.json(productData);
  } catch (error) {
    console.error('Debug - Error fetching products:', error);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Only admins can delete products' });
    }

    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    await product.deleteOne();

    // Remover todas as vendas relacionadas a esse produto
    await Sale.deleteMany({ 'products.productId': product._id });
    
    res.status(200).json({ message: 'Product and related sales deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(400).json({ error: error.message });
  }
});

// S3 Test endpoint (admin only)
app.get('/api/admin/test-s3', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Only admins can test S3 configuration' });
    }

    console.log('S3 test requested by admin:', req.user.email);
    
    // Test S3 configuration
    const { s3 } = require('./services/s3Service');
    const config = require('./config/config');
    
    // Try to list objects in bucket
    const listParams = {
      Bucket: config.aws.bucketName,
      MaxKeys: 1
    };
    
    try {
      await s3.listObjectsV2(listParams).promise();
      res.status(200).json({ 
        message: 'S3 configuration is working correctly',
        bucket: config.aws.bucketName,
        region: config.aws.region
      });
    } catch (s3Error) {
      console.error('S3 test failed:', s3Error);
      res.status(500).json({ 
        error: 'S3 configuration test failed',
        details: s3Error.message,
        code: s3Error.code
      });
    }
  } catch (error) {
    console.error('Error testing S3:', error);
    res.status(500).json({ error: error.message });
  }
});

// S3 Cleanup endpoint (admin only)
app.post('/api/admin/cleanup-s3', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Only admins can perform S3 cleanup' });
    }

    console.log('S3 cleanup requested by admin:', req.user.email);
    
    // Run cleanup in background
    cleanupS3Images()
      .then(() => {
        console.log('S3 cleanup completed successfully');
      })
      .catch(error => {
        console.error('S3 cleanup failed:', error);
      });

    res.status(200).json({ 
      message: 'S3 cleanup started. Check server logs for progress.' 
    });
  } catch (error) {
    console.error('Error starting S3 cleanup:', error);
    res.status(500).json({ error: error.message });
  }
});

// Custom Lists routes
app.post('/api/custom-lists', authenticate, async (req, res) => {
  try {
    const { name, description, products, sharedWith, isPublic } = req.body;
    
    const customList = new CustomList({
      name,
      description: description || '',
      products,
      sharedWith: sharedWith || [],
      isPublic: isPublic || false,
      userId: req.user._id
    });

    await customList.save();
    res.status(201).json(customList);
  } catch (error) {
    console.error('Error creating custom list:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get all custom lists (corrigir formato dos produtos)
app.get('/api/custom-lists', authenticate, async (req, res) => {
  try {
    const currentUserId = req.user._id;
    let lists;
    if (req.user.isAdmin) {
      lists = await CustomList.find();
    } else {
      lists = await CustomList.find({
        $or: [
          { userId: req.user._id },
          { sharedWith: req.user._id },
          { isPublic: true }
        ]
      });
    }
    
    // Para cada lista, filtrar produtos que existem
    const allProducts = await Product.find({}, '_id');
    const validProductIds = new Set(allProducts.map(p => p._id.toString()));
    
    // Guardar ids de listas a serem removidas
    const listsToRemove = [];
    for (const list of lists) {
      const originalLength = list.products.length;
      list.products = list.products.filter(item => {
        // Handle both old format (string) and new format (object with productId)
        let productId;
        if (typeof item === 'string') {
          productId = item;
        } else if (item && item.productId) {
          productId = item.productId;
        } else {
          return false; // Invalid item, filter it out
        }
        
        // Check if the productId is valid
        return validProductIds.has(productId.toString());
      });
      
      if (list.products.length !== originalLength) {
        await list.save();
      }
      // Se a lista ficou vazia, marcar para remover
      if (list.products.length === 0) {
        listsToRemove.push(list._id);
      }
    }
    
    // Remover listas vazias
    if (listsToRemove.length > 0) {
      await CustomList.deleteMany({ _id: { $in: listsToRemove } });
      // Remover as listas do array local
      lists = lists.filter(list => !listsToRemove.includes(list._id.toString()));
    }
    
    // Calcular estoque total disponível por produto para admin
    let productStockMap = new Map();
    if (req.user.isAdmin) {
      for (const list of lists) {
        for (const item of list.products) {
          const productId = item.productId.toString();
          const availableQty = item.availableQuantity || item.quantity || 0;
          
          if (productStockMap.has(productId)) {
            productStockMap.set(productId, productStockMap.get(productId) + availableQty);
          } else {
            productStockMap.set(productId, availableQty);
          }
        }
      }
    }
    
    // Popular e formatar para o frontend
    const populatedLists = await Promise.all(lists.map(async (list) => {
      const populatedProducts = await Promise.all(
        list.products.map(async (item) => {
          // Handle both old format (string) and new format (object with productId)
          let productId, quantity, availableQuantity;
          if (typeof item === 'string') {
            productId = item;
            quantity = 1; // Default quantity for old format
            availableQuantity = 1; // Default available quantity
          } else if (item && item.productId) {
            productId = item.productId;
            quantity = item.quantity || 1;
            availableQuantity = item.availableQuantity || item.quantity || 1;
          } else {
            // Skip invalid items
            return null;
          }
          
          const product = await Product.findById(productId);
          
          // Para admin, mostrar estoque total disponível
          let displayAvailableQuantity = availableQuantity;
          if (req.user.isAdmin) {
            displayAvailableQuantity = productStockMap.get(productId.toString()) || 0;
          }
          
          return {
            productId: productId,
            quantity: quantity,
            availableQuantity: availableQuantity,
            displayAvailableQuantity: displayAvailableQuantity,
            product: product
          };
        })
      );
      
      // Filter out null items (invalid products)
      const validProducts = populatedProducts.filter(item => item !== null);
      
      // Para admin, calcular se a lista está esgotada baseado no estoque total
      let isOutOfStockForAdmin = false;
      if (req.user.isAdmin) {
        isOutOfStockForAdmin = validProducts.every(product => product.displayAvailableQuantity === 0);
      }
      
      // Filtrar listas esgotadas para usuários não-admin
      if (!req.user.isAdmin && list.isOutOfStock) {
        // Verificar se o usuário tem unidades cadastradas na lista
        const hasUserUnits = validProducts.some(product => product.availableQuantity > 0);
        if (!hasUserUnits) {
          return null; // Não mostrar lista esgotada para usuários sem unidades
        }
      }
      
      return {
        ...list.toObject(),
        products: validProducts,
        isOutOfStockForAdmin: isOutOfStockForAdmin
      };
    }));
    
    // Filtrar listas nulas (esgotadas para usuários sem unidades)
    const filteredLists = populatedLists.filter(list => list !== null);
    
    res.json(filteredLists);
  } catch (error) {
    console.error('Error fetching custom lists:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update custom list (add/remove products)
app.put('/api/custom-lists/:listId', authenticate, async (req, res) => {
  try {
    const { listId } = req.params;
    const { name, description, products, sharedWith, isPublic } = req.body;
    const currentUserId = req.user._id;

    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
    }

    // Check if user has permission to edit (creator or admin)
    const hasEditPermission = req.user.isAdmin || 
                             list.userId.toString() === currentUserId.toString();
    
    if (!hasEditPermission) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Update list fields
    if (name !== undefined) list.name = name;
    if (description !== undefined) list.description = description;
    if (products !== undefined) {
      // Calcular diferenças de estoque antes de atualizar
      const oldProducts = new Map();
      list.products.forEach(item => {
        let productId, quantity;
        if (typeof item === 'string') {
          productId = item;
          quantity = 1;
        } else if (item && item.productId) {
          productId = item.productId.toString();
          quantity = item.quantity || 1;
        } else {
          return;
        }
        oldProducts.set(productId, quantity);
      });

      // Se products é um array de strings (IDs), converter para o novo formato
      if (Array.isArray(products) && products.length > 0 && typeof products[0] === 'string') {
        list.products = products.map(productId => ({ productId, quantity: 1 }));
      } else {
        list.products = products;
      }

      // Calcular diferenças e ajustar estoque
      const newProducts = new Map();
      list.products.forEach(item => {
        let productId, quantity;
        if (typeof item === 'string') {
          productId = item;
          quantity = 1;
        } else if (item && item.productId) {
          productId = item.productId.toString();
          quantity = item.quantity || 1;
        } else {
          return;
        }
        newProducts.set(productId, quantity);
      });

      // Ajustar estoque baseado nas diferenças
      for (const [productId, newQuantity] of newProducts) {
        const oldQuantity = oldProducts.get(productId) || 0;
        const difference = newQuantity - oldQuantity;
        
        if (difference !== 0) {
          const product = await Product.findById(productId);
          if (product) {
            if (difference > 0) {
              // Produto foi adicionado ou quantidade aumentou
              if (product.quantity >= difference) {
                product.quantity = Math.max(0, product.quantity - difference);
                await product.save();
              }
            } else {
              // Produto foi removido ou quantidade diminuiu
              product.quantity += Math.abs(difference);
              await product.save();
            }
          }
        }
      }

      // Remover produtos que não estão mais na lista
      for (const [productId, oldQuantity] of oldProducts) {
        if (!newProducts.has(productId)) {
          const product = await Product.findById(productId);
          if (product) {
            product.quantity += oldQuantity;
            await product.save();
          }
        }
      }
    }
    if (sharedWith !== undefined) list.sharedWith = sharedWith;
    if (isPublic !== undefined) list.isPublic = isPublic;

    await list.save();
    
    // Populate products before returning
    await list.populate('products.productId');
    
    // Transformar os dados para o formato esperado pelo frontend
    const transformedList = {
      ...list.toObject(),
      products: list.products.map(item => ({
        productId: item.productId?._id || item.productId,
        quantity: item.quantity,
        product: item.productId
      }))
    };
    
    res.json(transformedList);
  } catch (error) {
    console.error('Error updating custom list:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add product to custom list
app.post('/api/custom-lists/:listId/products/:productId', authenticate, async (req, res) => {
  try {
    const { listId, productId } = req.params;
    const { quantity } = req.body;
    const currentUserId = req.user._id;
    const qty = Math.max(1, parseInt(quantity) || 1);

    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
    }

    // Check if user has permission to edit
    const hasEditPermission = req.user.isAdmin || 
                             list.userId.toString() === currentUserId.toString();
    if (!hasEditPermission) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Check if product exists
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Verifica se já existe esse produto na lista
    const existing = list.products.find(p => {
      // Handle both old format (string) and new format (object with productId)
      let itemProductId;
      if (typeof p === 'string') {
        itemProductId = p;
      } else if (p && p.productId) {
        itemProductId = p.productId;
      } else {
        return false; // Invalid item, skip it
      }
      
      return itemProductId.toString() === productId;
    });
    
    if (existing) {
      // Se o produto já existe, adiciona a quantidade à lista E desconta do estoque
      existing.quantity += qty;
    } else {
      // Se é um produto novo na lista, adiciona e desconta do estoque
      list.products.push({ productId, quantity: qty });
    }
    await list.save();

    // Desconta do estoque do admin (sempre, independente se é novo ou existente)
    if (product.quantity >= qty) {
      product.quantity = Math.max(0, product.quantity - qty);
      await product.save();
    } else {
      console.error('Estoque insuficiente. Disponível:', product.quantity, 'Solicitado:', qty);
    }

    // Buscar a lista novamente para garantir que temos os dados corretos
    const updatedList = await CustomList.findById(listId);
    
    // Populate manualmente os produtos
    const populatedProducts = await Promise.all(
      updatedList.products.map(async (item) => {
        // Handle both old format (string) and new format (object with productId)
        let productId, quantity;
        if (typeof item === 'string') {
          productId = item;
          quantity = 1; // Default quantity for old format
        } else if (item && item.productId) {
          productId = item.productId;
          quantity = item.quantity || 1;
        } else {
          // Skip invalid items
          return null;
        }
        
        const product = await Product.findById(productId);
        return {
          productId: productId,
          quantity: quantity,
          product: product
        };
      })
    );
    
    // Filter out null items (invalid products)
    const validProducts = populatedProducts.filter(item => item !== null);
    
    // Formata para o frontend
    const transformedList = {
      ...updatedList.toObject(),
      products: validProducts
    };
    
    res.json(transformedList);
  } catch (error) {
    console.error('Error adding product to list:', error);
    res.status(500).json({ error: error.message });
  }
});

// Remove product from custom list
app.delete('/api/custom-lists/:listId/products/:productId', authenticate, async (req, res) => {
  try {
    const { listId, productId } = req.params;
    const currentUserId = req.user._id;

    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
    }

    // Check if user has permission to edit
    const hasEditPermission = req.user.isAdmin || 
                             list.userId.toString() === currentUserId.toString();
    
    if (!hasEditPermission) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Encontrar o produto na lista antes de remover para saber a quantidade
    const productToRemove = list.products.find(item => {
      // Handle both old format (string) and new format (object with productId)
      let itemProductId;
      if (typeof item === 'string') {
        itemProductId = item;
      } else if (item && item.productId) {
        itemProductId = item.productId;
      } else {
        return false;
      }
      
      return itemProductId.toString() === productId;
    });

    // Remove product from list
    list.products = list.products.filter(item => {
      // Handle both old format (string) and new format (object with productId)
      let itemProductId;
      if (typeof item === 'string') {
        itemProductId = item;
      } else if (item && item.productId) {
        itemProductId = item.productId;
      } else {
        return true; // Keep invalid items for now, they'll be filtered out later
      }
      
      return itemProductId.toString() !== productId;
    });
    await list.save();

    // Devolver a quantidade ao estoque se encontrou o produto
    if (productToRemove) {
      let quantityToReturn = 1; // Default para formato antigo
      if (productToRemove.quantity) {
        quantityToReturn = productToRemove.quantity;
      }
      
      const product = await Product.findById(productId);
      if (product) {
        product.quantity += quantityToReturn;
        await product.save();
      }
    }

    // Remover todas as vendas relacionadas a esse produto
    await Sale.deleteMany({ 'products.productId': productId });

    await list.populate({
      path: 'products',
      match: { _id: { $exists: true } }
    });
    res.json(list);
  } catch (error) {
    console.error('Error removing product from list:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add route to share list with users
app.post('/api/custom-lists/:listId/share', authenticate, async (req, res) => {
  try {
    const { listId } = req.params;
    const { userIds } = req.body;
    const currentUserId = req.user._id;

    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
    }

    // Check if user is the creator
    if (list.creator.toString() !== currentUserId.toString()) {
      return res.status(403).json({ error: 'Only the creator can share this list' });
    }

    // Validate that all users exist
    const users = await User.find({ _id: { $in: userIds } });
    if (users.length !== userIds.length) {
      return res.status(400).json({ error: 'One or more users not found' });
    }

    // Add new users to sharedWith array
    list.sharedWith = [...new Set([...list.sharedWith, ...userIds])];
    await list.save();

    res.json(list);
  } catch (error) {
    console.error('Error sharing list:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get specific custom list by ID (corrigir formato dos produtos)
app.get('/api/custom-lists/:listId', authenticate, async (req, res) => {
  try {
    const { listId } = req.params;
    const currentUserId = req.user._id;

    // Validate ObjectId format
    if (!listId.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ error: 'Invalid list ID format' });
    }

    const list = await CustomList.findById(listId);
    if (!list) {
      return res.status(404).json({ error: 'List not found' });
    }

    // Check if user has permission to view (creator, shared user, public list, or admin)
    const hasViewPermission = req.user.isAdmin || 
                             list.userId.toString() === currentUserId.toString() ||
                             list.sharedWith.includes(currentUserId) ||
                             list.isPublic;
    
    if (!hasViewPermission) {
      return res.status(403).json({ error: 'Permission denied' });
    }

    // Filtrar produtos que existem
    const allProducts = await Product.find({}, '_id');
    const validProductIds = new Set(allProducts.map(p => p._id.toString()));
    const originalLength = list.products.length;
    list.products = list.products.filter(item => {
      // Handle both old format (string) and new format (object with productId)
      let productId;
      if (typeof item === 'string') {
        productId = item;
      } else if (item && item.productId) {
        productId = item.productId;
      } else {
        return false; // Invalid item, filter it out
      }
      
      // Check if the productId is valid
      return validProductIds.has(productId.toString());
    });
    
    if (list.products.length !== originalLength) {
      await list.save();
    }
    // Se a lista ficou vazia, exclua
    if (list.products.length === 0) {
      await CustomList.deleteOne({ _id: list._id });
      return res.status(404).json({ error: 'List not found (empty after cleanup)' });
    }
    // Popular e formatar para o frontend
    const populatedProducts = await Promise.all(
      list.products.map(async (item) => {
        // Handle both old format (string) and new format (object with productId)
        let productId, quantity;
        if (typeof item === 'string') {
          productId = item;
          quantity = 1; // Default quantity for old format
        } else if (item && item.productId) {
          productId = item.productId;
          quantity = item.quantity || 1;
        } else {
          // Skip invalid items
          return null;
        }
        
        const product = await Product.findById(productId);
        return {
          productId: productId,
          quantity: quantity,
          product: product
        };
      })
    );
    
    // Filter out null items (invalid products)
    const validProducts = populatedProducts.filter(item => item !== null);
    const transformedList = {
      ...list.toObject(),
      products: validProducts
    };
    res.json(transformedList);
  } catch (error) {
    console.error('Error fetching custom list:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create admin user endpoint
app.post('/api/create-admin', async (req, res) => {
  try {
    const { name, email, cpf, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { cpf }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or CPF already exists' });
    }

    // Create admin user
    const admin = new User({
      name,
      email,
      cpf,
      password,
      isAdmin: true
    });
    await admin.save();
    
    res.status(201).json({ message: 'Admin user created successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Create admin user on server start
const createAdminUser = async () => {
  try {
    const adminExists = await User.findOne({ email: 'jhordan@admin.com' });
    if (!adminExists) {
      const admin = new User({
        name: 'Jhordan',
        email: 'jhordan@admin.com',
        cpf: '00000000000',
        password: '123',
        isAdmin: true
      });
      await admin.save();
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

// Get all users (admin only)
app.get('/api/users', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// Rotas de vendas
app.get('/api/sales', authenticate, async (req, res) => {
  try {
    const query = req.user.isAdmin ? {} : { userId: req.user._id };
    let sales = [];
    try {
      sales = await Sale.find(query)
        .populate('products.productId')
        .sort({ createdAt: -1 });
    } catch (err) {
      // Se der erro no populate (ex: produto órfão), retorna array vazio
      console.error('Erro ao buscar vendas (populate):', err);
      sales = [];
    }
    res.json(sales);
  } catch (error) {
    console.error('Error fetching sales:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas' });
  }
});

app.post('/api/sales', authenticate, async (req, res) => {
  try {
    const { products, total } = req.body;
    
    if (!products || !Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ message: 'Lista de produtos inválida' });
    }

    // Permitir total negativo para devoluções
    if (total === undefined || total === null || isNaN(total)) {
      return res.status(400).json({ message: 'Valor total inválido' });
    }

    // Verificar e atualizar estoque das listas customizadas
    for (const saleProduct of products) {
      const { productId, quantity } = saleProduct;
      
      // Buscar todas as listas customizadas que contêm este produto
      const customLists = await CustomList.find({
        'products.productId': productId,
        isOutOfStock: false // Apenas listas com estoque
      });

      // Atualizar estoque em cada lista
      for (const list of customLists) {
        await list.updateStock(productId, quantity);
      }
    }

    // Calcular comissão (30% do total)
    const commission = Number((total * 0.3).toFixed(2));

    const sale = new Sale({
      userId: req.user._id,
      products,
      total,
      commission
    });

    await sale.save();

    res.status(201).json(sale);
  } catch (error) {
    console.error('Erro ao criar venda:', error);
    res.status(500).json({ message: 'Erro ao criar venda' });
  }
});

// Rota para obter resumo de vendas (apenas admin)
app.get('/api/sales/summary', authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Acesso negado. Apenas administradores podem ver o resumo de vendas.' });
    }

    // Buscar todas as vendas com detalhes do usuário e produtos
    const sales = await Sale.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $lookup: {
          from: 'products',
          localField: 'products.productId',
          foreignField: '_id',
          as: 'productDetails'
        }
      },
      {
        $addFields: {
          products: {
            $map: {
              input: '$products',
              as: 'product',
              in: {
                $mergeObjects: [
                  '$$product',
                  {
                    productDetails: {
                      $arrayElemAt: [
                        {
                          $filter: {
                            input: '$productDetails',
                            as: 'pd',
                            cond: { $eq: ['$$pd._id', '$$product.productId'] }
                          }
                        },
                        0
                      ]
                    }
                  }
                ]
              }
            }
          }
        }
      },
      {
        $project: {
          _id: 1,
          userId: 1,
          userName: { $concat: ['$user.name', ' (', '$user.email', ')'] },
          products: {
            $map: {
              input: '$products',
              as: 'product',
              in: {
                productId: '$$product.productId',
                name: { $ifNull: ['$$product.productDetails.name', 'Produto não encontrado'] },
                quantity: { $toInt: '$$product.quantity' },
                price: { $toDouble: { $ifNull: ['$$product.productDetails.finalPrice', 0] } }
              }
            }
          },
          total: { $toDouble: '$total' },
          commission: { $toDouble: '$commission' },
          createdAt: 1
        }
      },
      {
        $sort: { createdAt: -1 }
      }
    ]);

    res.json(sales);
  } catch (error) {
    console.error('Erro ao buscar resumo de vendas:', error);
    res.status(500).json({ message: 'Erro ao buscar resumo de vendas' });
  }
});

// Rota para deletar vendas de um usuário específico (apenas admin)
app.delete('/api/sales/user/:userId', authenticate, async (req, res) => {
  try {
    // Verificar se o usuário é admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        message: 'Acesso negado. Apenas administradores podem zerar vendas.' 
      });
    }

    const { userId } = req.params;

    // Verificar se o usuário existe
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    // Deletar todas as vendas do usuário
    const result = await Sale.deleteMany({ userId: userId });
    
    console.log(`Vendas deletadas para o usuário ${userId}: ${result.deletedCount} vendas`);

    res.status(200).json({ 
      message: `Vendas zeradas com sucesso. ${result.deletedCount} vendas foram removidas.`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Erro ao zerar vendas do usuário:', error);
    res.status(500).json({ message: 'Erro interno do servidor ao zerar vendas' });
  }
});

// Rota para relatório de vendas fechadas (apenas admin)
app.get('/api/sales/closed-report', authenticate, async (req, res) => {
  try {
    // Verificar se o usuário é admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        message: 'Acesso negado. Apenas administradores podem acessar relatórios.' 
      });
    }

    const { month, year } = req.query;
    
    // Construir query para buscar vendas fechadas
    let query = { status: 'closed' };
    
    if (month && year) {
      const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
      const endDate = new Date(parseInt(year), parseInt(month), 1);
      query.closedAt = {
        $gte: startDate,
        $lt: endDate
      };
    } else if (year) {
      const startDate = new Date(parseInt(year), 0, 1);
      const endDate = new Date(parseInt(year) + 1, 0, 1);
      query.closedAt = {
        $gte: startDate,
        $lt: endDate
      };
    }

    // Buscar vendas fechadas com dados populados
    const sales = await Sale.find(query)
      .populate('userId', 'name email')
      .populate('products.productId')
      .sort({ closedAt: -1 });

    // Formatar dados para o frontend
    const formattedSales = sales.map(sale => {
      const closedDate = new Date(sale.closedAt);
      return {
        _id: sale._id,
        listName: sale.listName || 'Lista não identificada',
        userName: sale.userId ? sale.userId.name : 'Usuário não identificado',
        products: sale.products.map(product => ({
          productId: product.productId._id,
          name: product.productId.name,
          quantity: product.quantity,
          price: product.productId.finalPrice || 0,
          subtotal: product.quantity * (product.productId.finalPrice || 0)
        })),
        total: sale.total,
        commission: sale.commission,
        closedAt: sale.closedAt,
        month: (closedDate.getMonth() + 1).toString().padStart(2, '0'),
        year: closedDate.getFullYear().toString()
      };
    });

    res.json(formattedSales);
  } catch (error) {
    console.error('Erro ao buscar relatório de vendas fechadas:', error);
    res.status(500).json({ message: 'Erro ao buscar relatório de vendas fechadas' });
  }
});

// Rota para fechar inventário de um usuário específico (apenas admin)
app.post('/api/sales/close-user-inventory', authenticate, async (req, res) => {
  try {
    // Verificar se o usuário é admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        message: 'Acesso negado. Apenas administradores podem fechar inventários.' 
      });
    }

    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: 'ID do usuário é obrigatório' });
    }

    // Verificar se o usuário existe
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    // Buscar todas as vendas ativas do usuário
    const activeSales = await Sale.find({ 
      userId: userId,
      status: { $ne: 'closed' }
    }).populate('products.productId');

    if (activeSales.length === 0) {
      return res.status(400).json({ message: 'Nenhuma venda ativa encontrada para este usuário' });
    }

    // Buscar listas custom do usuário
    const customLists = await CustomList.find({ 
      userId: userId,
      status: { $ne: 'closed' }
    });

    let returnedProducts = 0;
    const closedSales = [];

    // Para cada lista custom, calcular produtos não vendidos e retornar ao estoque do admin
    for (const list of customLists) {
      // Calcular produtos vendidos desta lista
      const listSales = activeSales.filter(sale => 
        sale.listId && sale.listId.toString() === list._id.toString()
      );

      // Para cada produto da lista
      for (const productItem of list.products) {
        const soldQuantity = listSales.reduce((total, sale) => {
          const saleProduct = sale.products.find(p => 
            p.productId._id.toString() === productItem.productId.toString()
          );
          return total + (saleProduct ? saleProduct.quantity : 0);
        }, 0);

        const unsoldQuantity = productItem.quantity - soldQuantity;
        
        if (unsoldQuantity > 0) {
          // Retornar produtos não vendidos ao estoque do admin
          const product = await Product.findById(productItem.productId);
          if (product) {
            product.quantity += unsoldQuantity;
            await product.save();
            returnedProducts += unsoldQuantity;
            console.log(`Retornando ${unsoldQuantity} unidades do produto ${product.name} ao estoque do admin`);
          }
        }
      }
    }

    // Marcar vendas como fechadas e salvar na página de vendas fechadas
    for (const sale of activeSales) {
      sale.status = 'closed';
      sale.closedAt = new Date();
      
      // Buscar nome da lista se existir
      if (sale.listId) {
        const list = customLists.find(l => l._id.toString() === sale.listId.toString());
        if (list) {
          sale.listName = list.name;
        }
      }
      
      await sale.save();
      closedSales.push(sale);
    }

    // EXCLUIR todas as listas custom do usuário após processar as vendas
    const deletedListsCount = await CustomList.deleteMany({ 
      userId: userId,
      status: { $ne: 'closed' }
    });

    res.json({ 
      message: `Inventário fechado com sucesso para ${user.name}. ${returnedProducts} produtos retornaram ao estoque do administrador. ${deletedListsCount.deletedCount} listas foram excluídas.`,
      returnedProducts,
      closedSalesCount: closedSales.length,
      deletedListsCount: deletedListsCount.deletedCount
    });
  } catch (error) {
    console.error('Erro ao fechar inventário do usuário:', error);
    res.status(500).json({ message: 'Erro ao fechar inventário do usuário' });
  }
});

// Rota para obter venda em progresso
app.get('/api/draft-sales', authenticate, async (req, res) => {
  try {
    const draftSale = await DraftSale.findOne({ userId: req.user._id })
      .populate('products.productId');
    
    if (!draftSale) {
      return res.json({ products: [], total: 0, commission: 0 });
    }
    
    res.json(draftSale);
  } catch (error) {
    console.error('Erro ao buscar venda em progresso:', error);
    res.status(500).json({ message: 'Erro ao buscar venda em progresso' });
  }
});

// Rota para salvar/atualizar venda em progresso
app.post('/api/draft-sales', authenticate, async (req, res) => {
  try {
    const { products, total, commission } = req.body;
    
    const draftSale = await DraftSale.findOneAndUpdate(
      { userId: req.user._id },
      {
        products,
        total: total || 0,
        commission: commission || 0
      },
      { 
        upsert: true, 
        new: true,
        runValidators: true
      }
    ).populate('products.productId');
    
    res.json(draftSale);
  } catch (error) {
    console.error('Erro ao salvar venda em progresso:', error);
    res.status(500).json({ message: 'Erro ao salvar venda em progresso' });
  }
});

// Rota para limpar venda em progresso
app.delete('/api/draft-sales', authenticate, async (req, res) => {
  try {
    await DraftSale.findOneAndDelete({ userId: req.user._id });
    res.json({ message: 'Venda em progresso removida com sucesso' });
  } catch (error) {
    console.error('Erro ao limpar venda em progresso:', error);
    res.status(500).json({ message: 'Erro ao limpar venda em progresso' });
  }
});

// ===== ROTAS DE CONDICIONAIS =====

// Rota para criar um novo condicional
app.post('/api/condicionais', authenticate, async (req, res) => {
  try {
    const { clientName, products, discount = 0, notes = '' } = req.body;
    
    if (!clientName || !products || !Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ message: 'Dados inválidos para criar condicional' });
    }

    // Calcular totais
    const totalOriginal = products.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const totalWithDiscount = totalOriginal - discount;

    const condicional = new Condicional({
      sellerId: req.user._id,
      clientName,
      products,
      totalOriginal,
      discount,
      totalWithDiscount,
      notes
    });

    await condicional.save();

    // Popular os produtos para retornar
    await condicional.populate('products.productId');

    res.status(201).json(condicional);
  } catch (error) {
    console.error('Erro ao criar condicional:', error);
    res.status(500).json({ message: 'Erro ao criar condicional' });
  }
});

// Rota para listar condicionais do vendedor
app.get('/api/condicionais', authenticate, async (req, res) => {
  try {
    const { status } = req.query;
    let query = { sellerId: req.user._id };
    
    if (status && ['aberto', 'fechado', 'excluido'].includes(status)) {
      query.status = status;
    }

    const condicionais = await Condicional.find(query)
      .populate('products.productId')
      .populate('saleId')
      .sort({ createdAt: -1 });

    res.json(condicionais);
  } catch (error) {
    console.error('Erro ao buscar condicionais:', error);
    res.status(500).json({ message: 'Erro ao buscar condicionais' });
  }
});

// Rota para obter um condicional específico
app.get('/api/condicionais/:id', authenticate, async (req, res) => {
  try {
    const condicional = await Condicional.findOne({
      _id: req.params.id,
      sellerId: req.user._id
    })
    .populate('products.productId')
    .populate('saleId');

    if (!condicional) {
      return res.status(404).json({ message: 'Condicional não encontrado' });
    }

    res.json(condicional);
  } catch (error) {
    console.error('Erro ao buscar condicional:', error);
    res.status(500).json({ message: 'Erro ao buscar condicional' });
  }
});

// Rota para atualizar um condicional
app.put('/api/condicionais/:id', authenticate, async (req, res) => {
  try {
    const { clientName, products, discount, notes } = req.body;
    
    const condicional = await Condicional.findOne({
      _id: req.params.id,
      sellerId: req.user._id,
      status: 'aberto' // Só permite editar condicionais abertos
    });

    if (!condicional) {
      return res.status(404).json({ message: 'Condicional não encontrado ou não pode ser editado' });
    }

    // Atualizar campos
    if (clientName) condicional.clientName = clientName;
    if (products) condicional.products = products;
    if (discount !== undefined) condicional.discount = discount;
    if (notes !== undefined) condicional.notes = notes;

    await condicional.save();
    await condicional.populate('products.productId');

    res.json(condicional);
  } catch (error) {
    console.error('Erro ao atualizar condicional:', error);
    res.status(500).json({ message: 'Erro ao atualizar condicional' });
  }
});

// Rota para fechar um condicional (converter em venda)
app.post('/api/condicionais/:id/close', authenticate, async (req, res) => {
  try {
    const condicional = await Condicional.findOne({
      _id: req.params.id,
      sellerId: req.user._id,
      status: 'aberto'
    }).populate('products.productId');

    if (!condicional) {
      return res.status(404).json({ message: 'Condicional não encontrado ou já fechado' });
    }

    // Verificar e atualizar estoque das listas customizadas
    for (const condicionalProduct of condicional.products) {
      const { productId, quantity } = condicionalProduct;
      
      // Buscar todas as listas customizadas que contêm este produto
      const customLists = await CustomList.find({
        'products.productId': productId._id,
        isOutOfStock: false // Apenas listas com estoque
      });

      // Atualizar estoque em cada lista
      for (const list of customLists) {
        await list.updateStock(productId._id, quantity);
      }
    }

    // Criar uma nova venda com os produtos do condicional
    const sale = new Sale({
      userId: req.user._id,
      products: condicional.products.map(item => ({
        productId: item.productId._id,
        quantity: item.quantity
      })),
      total: condicional.totalWithDiscount,
      commission: condicional.totalWithDiscount * 0.3 // 30% de comissão
    });

    await sale.save();

    // Fechar o condicional
    await condicional.close(sale._id);

    res.json({ 
      message: 'Condicional fechado com sucesso',
      condicional,
      sale
    });
  } catch (error) {
    console.error('Erro ao fechar condicional:', error);
    res.status(500).json({ message: 'Erro ao fechar condicional' });
  }
});

// Rota para excluir um condicional (marcar como excluído)
app.delete('/api/condicionais/:id', authenticate, async (req, res) => {
  try {
    const condicional = await Condicional.findOne({
      _id: req.params.id,
      sellerId: req.user._id,
      status: 'aberto'
    });

    if (!condicional) {
      return res.status(404).json({ message: 'Condicional não encontrado ou já não está aberto' });
    }

    await condicional.delete();

    res.json({ message: 'Condicional excluído com sucesso' });
  } catch (error) {
    console.error('Erro ao excluir condicional:', error);
    res.status(500).json({ message: 'Erro ao excluir condicional' });
  }
});

// Rota para inicializar estoque das listas customizadas (apenas admin)
app.post('/api/custom-lists/initialize-stock', authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Acesso negado. Apenas administradores podem inicializar estoque.' });
    }

    const lists = await CustomList.find();
    let updatedCount = 0;

    for (const list of lists) {
      let needsUpdate = false;
      
      for (const product of list.products) {
        if (product.availableQuantity === undefined) {
          product.availableQuantity = product.quantity;
          needsUpdate = true;
        }
      }
      
      if (needsUpdate) {
        await list.save();
        updatedCount++;
      }
    }

    res.json({ 
      message: `Estoque inicializado com sucesso. ${updatedCount} listas foram atualizadas.`,
      updatedCount 
    });
  } catch (error) {
    console.error('Erro ao inicializar estoque:', error);
    res.status(500).json({ message: 'Erro ao inicializar estoque' });
  }
});

// Rota para fechar estoque de uma lista específica
app.post('/api/custom-lists/close-stock', authenticate, async (req, res) => {
  try {
    const { listId } = req.body;
    
    if (!listId) {
      return res.status(400).json({ message: 'ID da lista é obrigatório' });
    }

    // Buscar a lista custom
    const customList = await CustomList.findById(listId).populate('userId', 'name email');
    
    if (!customList) {
      return res.status(404).json({ message: 'Lista não encontrada' });
    }

    // Verificar se o usuário tem permissão para fechar esta lista
    if (customList.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      return res.status(403).json({ message: 'Acesso negado. Você só pode fechar suas próprias listas.' });
    }

    // Buscar vendas desta lista
    const sales = await Sale.find({ 
      userId: customList.userId._id,
      listId: listId 
    }).populate('products.productId');

    let returnedProducts = 0;

    // Para cada produto da lista, calcular quantos não foram vendidos
    for (const productItem of customList.products) {
      const soldQuantity = sales.reduce((total, sale) => {
        const saleProduct = sale.products.find(p => p.productId._id.toString() === productItem.productId.toString());
        return total + (saleProduct ? saleProduct.quantity : 0);
      }, 0);

      const unsoldQuantity = productItem.quantity - soldQuantity;
      
      if (unsoldQuantity > 0) {
        // Retornar produtos não vendidos ao estoque do admin
        const product = await Product.findById(productItem.productId);
        if (product) {
          product.quantity += unsoldQuantity;
          await product.save();
          returnedProducts += unsoldQuantity;
          console.log(`Retornando ${unsoldQuantity} unidades do produto ${product.name} ao estoque do admin`);
        }
      }
    }

    // Marcar vendas como fechadas
    for (const sale of sales) {
      sale.status = 'closed';
      sale.closedAt = new Date();
      sale.listName = customList.name;
      await sale.save();
    }

    // EXCLUIR a lista após processar as vendas
    await CustomList.findByIdAndDelete(listId);

    res.json({ 
      message: `Estoque fechado com sucesso. ${returnedProducts} produtos retornaram ao estoque do administrador. Lista excluída.`,
      returnedProducts 
    });
  } catch (error) {
    console.error('Erro ao fechar estoque:', error);
    res.status(500).json({ message: 'Erro ao fechar estoque' });
  }
});

// Rota para fechar inventário de um usuário específico (apenas admin)
app.post('/api/sales/close-user-inventory', authenticate, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ message: 'Acesso negado. Apenas administradores podem fechar inventários.' });
    }

    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ message: 'ID do usuário é obrigatório' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const userCustomLists = await CustomList.find({ userId: userId, status: { $ne: 'closed' } });
    let totalReturnedProducts = 0;
    let totalClosedSales = 0;

    for (const list of userCustomLists) {
      // Calculate unsold quantity for each product in the list
      for (const productInList of list.products) {
        const soldQuantity = await Sale.aggregate([
          { $match: { userId: userId, listId: list._id, 'products.productId': productInList.productId } },
          { $unwind: '$products' },
          { $match: { 'products.productId': productInList.productId } },
          { $group: { _id: null, totalSold: { $sum: '$products.quantity' } } }
        ]);

        const currentSold = soldQuantity.length > 0 ? soldQuantity[0].totalSold : 0;
        const unsoldQuantity = productInList.quantity - currentSold;

        if (unsoldQuantity > 0) {
          await Product.findByIdAndUpdate(productInList.productId, { $inc: { quantity: unsoldQuantity } });
          totalReturnedProducts += unsoldQuantity;
          console.log(`✅ Retornou ${unsoldQuantity} unidades do produto ${productInList.productId} (Lista: ${list._id}) para o estoque do admin.`);
        }
      }

      // Mark sales associated with this list as closed
      await Sale.updateMany(
        { userId: userId, listId: list._id, status: { $ne: 'closed' } },
        { $set: { status: 'closed', closedAt: new Date(), listName: list.name } }
      );
      const closedSalesCount = await Sale.countDocuments({ userId: userId, listId: list._id, status: 'closed' });
      totalClosedSales += closedSalesCount;

      // Delete the custom list
      await CustomList.findByIdAndDelete(list._id);
      console.log(`🗑️ Lista customizada ${list._id} (Nome: ${list.name}) do usuário ${user.name} excluída.`);
    }

    res.status(200).json({
      message: `Inventário do usuário ${user.name} fechado com sucesso. ${totalReturnedProducts} produtos não vendidos retornaram ao estoque do admin e ${userCustomLists.length} listas foram excluídas.`,
      returnedProducts: totalReturnedProducts,
      closedLists: userCustomLists.length,
      closedSales: totalClosedSales
    });
  } catch (error) {
    console.error('❌ Erro ao fechar inventário do usuário:', error);
    res.status(500).json({ message: 'Erro ao fechar inventário do usuário', error: error.message });
  }
});

// Test endpoint to check if server is running
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend is running!', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Rota temporária para verificar status dos produtos e listas (sem autenticação para debug)
app.get('/debug/status', async (req, res) => {
  try {
    console.log('🔍 Verificando status do sistema...');

    // Contar produtos
    const productsCount = await Product.countDocuments();
    const productsWithStock = await Product.countDocuments({ quantity: { $gt: 0 } });
    const productsOutOfStock = await Product.countDocuments({ quantity: { $lte: 0 } });

    // Contar listas custom
    const customListsCount = await CustomList.countDocuments();
    const activeListsCount = await CustomList.countDocuments({ status: 'active' });
    const closedListsCount = await CustomList.countDocuments({ status: 'closed' });

    // Contar vendas
    const salesCount = await Sale.countDocuments();
    const activeSalesCount = await Sale.countDocuments({ status: 'active' });
    const closedSalesCount = await Sale.countDocuments({ status: 'closed' });

    // Buscar alguns produtos para exemplo
    const sampleProducts = await Product.find().limit(5).select('name quantity');

    // Buscar algumas listas para exemplo
    const sampleLists = await CustomList.find().limit(3).select('name status products');

    console.log('✅ Status verificado com sucesso');

    res.json({
      products: {
        total: productsCount,
        withStock: productsWithStock,
        outOfStock: productsOutOfStock,
        sample: sampleProducts
      },
      customLists: {
        total: customListsCount,
        active: activeListsCount,
        closed: closedListsCount,
        sample: sampleLists
      },
      sales: {
        total: salesCount,
        active: activeSalesCount,
        closed: closedSalesCount
      }
    });
  } catch (error) {
    console.error('❌ Erro ao verificar status:', error);
    res.status(500).json({ message: 'Erro ao verificar status', error: error.message });
  }
});

// Rota para migração de dados existentes (apenas admin)
app.post('/api/migrate-data', async (req, res) => {
  try {
    // Verificar se o usuário é admin (temporariamente desabilitado para debug)
    // if (!req.user.isAdmin) {
    //   return res.status(403).json({ 
    //     message: 'Acesso negado. Apenas administradores podem executar migrações.' 
    //   });
    // }

    console.log('🔄 Iniciando migração de dados...');

    // 1. Buscar todas as listas custom que foram marcadas como fechadas mas não foram excluídas
    const closedLists = await CustomList.find({ status: 'closed' });
    console.log(`📋 Encontradas ${closedLists.length} listas marcadas como fechadas`);

    // 2. Buscar listas ativas que têm vendas fechadas (deveriam estar fechadas)
    const activeLists = await CustomList.find();
    console.log(`🔍 Encontradas ${activeLists.length} listas no total`);
    const listsToProcess = [];
    const orphanedLists = [];
    
    for (const list of activeLists) {
      const closedSalesCount = await Sale.countDocuments({ 
        userId: list.userId, 
        listId: list._id, 
        status: 'closed' 
      });
      
      if (closedSalesCount > 0) {
        listsToProcess.push(list);
        console.log(`📋 Lista ativa ${list.name} tem ${closedSalesCount} vendas fechadas - será processada`);
      } else {
        // Lista ativa sem vendas (lista órfã)
        orphanedLists.push(list);
        console.log(`📋 Lista ativa ${list.name} não tem vendas - será processada como órfã`);
      }
    }
    
    // Se não há listas órfãs detectadas, mas há listas ativas, processar todas como órfãs
    if (orphanedLists.length === 0 && activeLists.length > 0) {
      console.log(`📋 Nenhuma lista órfã detectada, mas há ${activeLists.length} listas ativas. Processando todas como órfãs.`);
      orphanedLists.push(...activeLists);
    }
    
    console.log(`📋 Encontradas ${listsToProcess.length} listas ativas com vendas fechadas`);
    console.log(`📋 Encontradas ${orphanedLists.length} listas ativas órfãs (sem vendas)`);

    let deletedListsCount = 0;
    let returnedProductsCount = 0;

    // 3. Processar todas as listas (fechadas + ativas com vendas fechadas + listas órfãs)
    const allListsToProcess = [...closedLists, ...listsToProcess, ...orphanedLists];
    console.log(`🔄 Processando ${allListsToProcess.length} listas no total`);
    
    for (const list of allListsToProcess) {
      console.log(`🔄 Processando lista: ${list.name} (ID: ${list._id})`);

      // Buscar vendas desta lista
      const sales = await Sale.find({ 
        userId: list.userId,
        listId: list._id 
      }).populate('products.productId');

      // Para cada produto da lista, calcular produtos não vendidos
      for (const productItem of list.products) {
        const soldQuantity = sales.reduce((total, sale) => {
          const saleProduct = sale.products.find(p => 
            p.productId._id.toString() === productItem.productId.toString()
          );
          return total + (saleProduct ? saleProduct.quantity : 0);
        }, 0);

        const unsoldQuantity = productItem.quantity - soldQuantity;
        
        if (unsoldQuantity > 0) {
          // Retornar produtos não vendidos ao estoque do admin
          const product = await Product.findById(productItem.productId);
          if (product) {
            product.quantity += unsoldQuantity;
            await product.save();
            returnedProductsCount += unsoldQuantity;
            console.log(`📦 Retornando ${unsoldQuantity} unidades do produto ${product.name} ao estoque do admin`);
          }
        }
      }

      // Marcar vendas como fechadas se ainda não estiverem
      for (const sale of sales) {
        if (sale.status !== 'closed') {
          sale.status = 'closed';
          sale.closedAt = sale.closedAt || new Date();
          sale.listName = list.name;
          await sale.save();
          console.log(`✅ Venda ${sale._id} marcada como fechada`);
        }
      }

      // Excluir a lista
      await CustomList.findByIdAndDelete(list._id);
      deletedListsCount++;
      console.log(`🗑️ Lista ${list.name} excluída`);
    }

    // 3. Buscar vendas que têm listId mas a lista não existe mais
    const orphanedSales = await Sale.find({
      listId: { $exists: true, $ne: null },
      status: { $ne: 'closed' }
    });

    console.log(`🔍 Encontradas ${orphanedSales.length} vendas órfãs (com listId mas lista não existe)`);

    for (const sale of orphanedSales) {
      // Verificar se a lista ainda existe
      const listExists = await CustomList.findById(sale.listId);
      if (!listExists) {
        // Se a lista não existe mais, marcar a venda como fechada
        sale.status = 'closed';
        sale.closedAt = new Date();
        sale.listName = 'Lista removida';
        await sale.save();
        console.log(`✅ Venda órfã ${sale._id} marcada como fechada`);
      }
    }

    // 4. Processar vendas sem listId (vendas órfãs)
    const salesWithoutListId = await Sale.find({
      listId: { $exists: false },
      status: 'closed'
    });

    console.log(`🔍 Encontradas ${salesWithoutListId.length} vendas fechadas sem listId`);

    // Agrupar vendas por usuário
    const salesByUser = {};
    for (const sale of salesWithoutListId) {
      if (!salesByUser[sale.userId]) {
        salesByUser[sale.userId] = [];
      }
      salesByUser[sale.userId].push(sale);
    }

    // Para cada usuário com vendas órfãs, verificar se tem lista ativa
    for (const [userId, sales] of Object.entries(salesByUser)) {
      const userList = await CustomList.findOne({ 
        userId: userId, 
        status: 'active' 
      });

      if (userList) {
        console.log(`🔄 Processando vendas órfãs do usuário ${userId} com lista ativa ${userList.name}`);

        // Associar vendas à lista
        for (const sale of sales) {
          sale.listId = userList._id;
          sale.listName = userList.name;
          await sale.save();
          console.log(`✅ Venda ${sale._id} associada à lista ${userList.name}`);
        }

        // Calcular produtos não vendidos da lista
        for (const productInList of userList.products) {
          const soldQuantity = sales.reduce((total, sale) => {
            const saleProduct = sale.products.find(p => 
              p.productId.toString() === productInList.productId.toString()
            );
            return total + (saleProduct ? saleProduct.quantity : 0);
          }, 0);

          const unsoldQuantity = productInList.quantity - soldQuantity;
          
          if (unsoldQuantity > 0) {
            // Retornar produtos não vendidos ao estoque do admin
            const product = await Product.findById(productInList.productId);
            if (product) {
              product.quantity += unsoldQuantity;
              await product.save();
              returnedProductsCount += unsoldQuantity;
              console.log(`📦 Retornando ${unsoldQuantity} unidades do produto ${product.name} ao estoque do admin`);
            }
          }
        }

        // Excluir a lista
        await CustomList.findByIdAndDelete(userList._id);
        deletedListsCount++;
        console.log(`🗑️ Lista ${userList.name} excluída após processar vendas órfãs`);
      } else {
        // Usuário tem vendas órfãs mas não tem lista ativa
        console.log(`🔄 Usuário ${userId} tem ${sales.length} vendas órfãs mas não tem lista ativa`);
        
        // Para vendas órfãs, não retornamos produtos ao estoque
        // porque os produtos já foram vendidos e não temos a lista original
        // para calcular o que não foi vendido
        
        // Marcar vendas como processadas
        for (const sale of sales) {
          sale.listName = 'Vendas Órfãs Processadas';
          await sale.save();
          console.log(`✅ Venda órfã ${sale._id} marcada como processada`);
        }
      }
    }

    // 4. Verificar produtos que podem ter estoque inconsistente
    const products = await Product.find();
    let fixedProductsCount = 0;

    for (const product of products) {
      if (product.quantity < 0) {
        product.quantity = 0;
        await product.save();
        fixedProductsCount++;
        console.log(`🔧 Produto ${product.name} com estoque negativo corrigido para 0`);
      }
    }

    // 5. Criar usuário padrão se não existir
    const defaultEmail = 'neusaaraujo@gmail.com';
    const existingUser = await User.findOne({ email: defaultEmail });
    
    if (!existingUser) {
      const defaultUser = new User({
        name: 'Neusa Araujo',
        email: defaultEmail,
        password: 'neusaaraujo',
        isAdmin: false
      });
      
      await defaultUser.save();
      console.log('✅ Usuário padrão criado:', defaultEmail);
    } else {
      console.log('ℹ️ Usuário padrão já existe:', defaultEmail);
    }

    console.log('✅ Migração concluída com sucesso!');

    res.json({
      message: 'Migração de dados concluída com sucesso!',
      summary: {
        closedListsProcessed: closedLists.length,
        listsDeleted: deletedListsCount,
        productsReturned: returnedProductsCount,
        orphanedSalesFixed: orphanedSales.length,
        productsFixed: fixedProductsCount,
        defaultUserCreated: !existingUser
      }
    });

  } catch (error) {
    console.error('❌ Erro durante a migração:', error);
    res.status(500).json({ 
      message: 'Erro durante a migração de dados',
      error: error.message 
    });
  }
});

// Rota raiz para mostrar todas as requisições disponíveis
app.get('/', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Lis - Documentação</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            color: white;
        }

        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .info-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .info-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .info-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.15);
        }

        .info-card h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3rem;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }

        .endpoints-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .endpoint-section {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }

        .endpoint-section:hover {
            transform: translateY(-3px);
        }

        .endpoint-section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .endpoint-section h2::before {
            content: '';
            width: 4px;
            height: 25px;
            background: #667eea;
            border-radius: 2px;
        }

        .endpoint-item {
            margin-bottom: 15px;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            transition: all 0.3s ease;
        }

        .endpoint-item:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }

        .method {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.8rem;
            margin-right: 10px;
            min-width: 60px;
            text-align: center;
        }

        .method.get { background: #28a745; color: white; }
        .method.post { background: #007bff; color: white; }
        .method.put { background: #ffc107; color: black; }
        .method.delete { background: #dc3545; color: white; }

        .endpoint-path {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #495057;
        }

        .endpoint-description {
            margin-top: 5px;
            color: #6c757d;
            font-size: 0.9rem;
        }

        .auth-note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #856404;
        }

        .auth-note strong {
            color: #d63031;
        }

        .cors-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #0c5460;
        }

        .footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            opacity: 0.8;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 2rem;
            }
            
            .endpoints-grid {
                grid-template-columns: 1fr;
            }
            
            .endpoint-item {
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 API Lis</h1>
            <p>Documentação Completa das Requisições Disponíveis</p>
        </div>

        <div class="info-cards">
            <div class="info-card">
                <h3>📊 Informações Gerais</h3>
                <p><strong>Versão:</strong> 1.0.0</p>
                <p><strong>Base URL:</strong> ${req.protocol}://${req.get('host')}</p>
                <p><strong>Status:</strong> <span style="color: #28a745;">🟢 Online</span></p>
            </div>
            
            <div class="info-card">
                <h3>🔐 Autenticação</h3>
                <p>A maioria das rotas requer autenticação via token JWT</p>
                <p><strong>Formato:</strong> Authorization: Bearer &lt;token&gt;</p>
            </div>
            
            <div class="info-card">
                <h3>🌐 CORS</h3>
                <p><strong>Origens permitidas:</strong></p>
                <p>• http://localhost:3000</p>
                <p>• http://localhost:3001</p>
                <p>• http://localhost:3005</p>
                <p>• https://www.jhorello.com.br</p>
                <p>• https://frontend-lis.vercel.app</p>
            </div>
        </div>

        <div class="auth-note">
            <strong>⚠️ Nota:</strong> A maioria das rotas requer autenticação. Use o endpoint <code>POST /api/login</code> para obter um token JWT.
        </div>

        <div class="endpoints-grid">
            <div class="endpoint-section">
                <h2>🔐 Autenticação</h2>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/register</span>
                    <div class="endpoint-description">Registrar novo usuário</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/login</span>
                    <div class="endpoint-description">Fazer login e obter token JWT</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/create-admin</span>
                    <div class="endpoint-description">Criar usuário administrador</div>
                </div>
            </div>

            <div class="endpoint-section">
                <h2>👥 Usuários</h2>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/users</span>
                    <div class="endpoint-description">Listar todos os usuários (apenas admin)</div>
                </div>
            </div>

            <div class="endpoint-section">
                <h2>📦 Produtos</h2>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/products</span>
                    <div class="endpoint-description">Listar produtos (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/products</span>
                    <div class="endpoint-description">Criar novo produto (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method put">PUT</span>
                    <span class="endpoint-path">/api/products/:id</span>
                    <div class="endpoint-description">Atualizar produto (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method delete">DELETE</span>
                    <span class="endpoint-path">/api/products/:id</span>
                    <div class="endpoint-description">Deletar produto (apenas admin)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/debug/products</span>
                    <div class="endpoint-description">Debug - Listar produtos (sem autenticação)</div>
                </div>
            </div>

            <div class="endpoint-section">
                <h2>📋 Listas Personalizadas</h2>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/custom-lists</span>
                    <div class="endpoint-description">Listar listas personalizadas (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/custom-lists</span>
                    <div class="endpoint-description">Criar nova lista personalizada (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/custom-lists/:listId</span>
                    <div class="endpoint-description">Obter lista específica (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method put">PUT</span>
                    <span class="endpoint-path">/api/custom-lists/:listId</span>
                    <div class="endpoint-description">Atualizar lista personalizada (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/custom-lists/:listId/products/:productId</span>
                    <div class="endpoint-description">Adicionar produto à lista (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method delete">DELETE</span>
                    <span class="endpoint-path">/api/custom-lists/:listId/products/:productId</span>
                    <div class="endpoint-description">Remover produto da lista (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/custom-lists/:listId/share</span>
                    <div class="endpoint-description">Compartilhar lista com usuários (requer autenticação)</div>
                </div>
            </div>

            <div class="endpoint-section">
                <h2>💰 Vendas</h2>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/sales</span>
                    <div class="endpoint-description">Listar vendas (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/sales</span>
                    <div class="endpoint-description">Criar nova venda (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/sales/summary</span>
                    <div class="endpoint-description">Resumo de vendas (apenas admin)</div>
                </div>
            </div>

            <div class="endpoint-section">
                <h2>⏳ Vendas em Progresso</h2>
                <div class="endpoint-item">
                    <span class="method get">GET</span>
                    <span class="endpoint-path">/api/draft-sales</span>
                    <div class="endpoint-description">Obter venda em progresso (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method post">POST</span>
                    <span class="endpoint-path">/api/draft-sales</span>
                    <div class="endpoint-description">Salvar/atualizar venda em progresso (requer autenticação)</div>
                </div>
                <div class="endpoint-item">
                    <span class="method delete">DELETE</span>
                    <span class="endpoint-path">/api/draft-sales</span>
                    <div class="endpoint-description">Limpar venda em progresso (requer autenticação)</div>
                </div>
            </div>
        </div>

        <div class="cors-info">
            <strong>🌐 CORS Configurado:</strong> A API aceita requisições dos domínios localhost:3000, localhost:3001, localhost:3005, https://www.jhorello.com.br e https://frontend-lis.vercel.app com os métodos GET, POST, PUT, DELETE e OPTIONS.
        </div>

        <div class="footer">
            <p>© 2024 API Lis - Sistema de Gerenciamento de Produtos e Vendas</p>
        </div>
    </div>
</body>
</html>`;

  res.send(html);
});

// Global error handling middleware
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  // Handle multer errors
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size must be less than 15MB' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Only one file is allowed' });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'Unexpected file field' });
    }
    return res.status(400).json({ error: 'File upload error' });
  }
  
  // Handle other errors
  if (error.message === 'Only image files are allowed') {
    return res.status(400).json({ error: 'Only image files are allowed' });
  }
  
  // Default error response
  res.status(500).json({ error: 'Internal server error' });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Version endpoint
app.get('/version', (req, res) => {
  res.json({ 
    version: '1.0.0',
    name: 'LIS MODAS Backend API',
    description: 'Sistema de Gerenciamento de Produtos e Vendas'
  });
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api`);
  console.log(`🌐 Direct API available at http://localhost:${PORT}`);
  console.log(`🏥 Health check at http://localhost:${PORT}/health`);
  console.log(`📋 Version info at http://localhost:${PORT}/version`);
  console.log(`🌐 CORS enabled for development`);
});