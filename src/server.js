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
    origin: ["http://localhost:3000", "http://localhost:3005", "lismodas.com.br", "https://www.lismodas.com.br"],
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      "http://localhost:3000", 
      "http://localhost:3005",
      "http://localhost:8081", 
      "https://frontend-lis.vercel.app", 
      "https://lismodas.com.br",
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
    
    const allowedOrigins = ["http://localhost:3000", "http://localhost:3005", "https://frontend-lis.vercel.app", "https://www.jhorello.com.br"];
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

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
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
      return res.status(400).json({ error: 'File size must be less than 5MB' });
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
      
      // Upload new image to S3
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
      return res.status(400).json({ error: 'File size must be less than 5MB' });
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
      // Admins can see all products
    const products = await Product.find();
      return res.json(products);
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

app.get('/api/custom-lists', authenticate, async (req, res) => {
  try {
    
    if (req.user.isAdmin) {
      // Admins can see all lists
      const lists = await CustomList.find().populate('products');
      return res.json(lists);
    }

    // For regular users, only show their own lists and shared lists
    const lists = await CustomList.find({
      $or: [
        { userId: req.user._id },
        { sharedWith: req.user._id },
        { isPublic: true }
      ]
    }).populate('products');

    res.json(lists);
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
    if (products !== undefined) list.products = products;
    if (sharedWith !== undefined) list.sharedWith = sharedWith;
    if (isPublic !== undefined) list.isPublic = isPublic;

    await list.save();
    
    // Populate products before returning
    await list.populate('products');
    
    res.json(list);
  } catch (error) {
    console.error('Error updating custom list:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add product to custom list
app.post('/api/custom-lists/:listId/products/:productId', authenticate, async (req, res) => {
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

    // Check if product exists
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Add product if not already in list
    if (!list.products.includes(productId)) {
      list.products.push(productId);
      await list.save();
    }

    await list.populate('products');
    res.json(list);
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

    // Remove product from list
    list.products = list.products.filter(id => id.toString() !== productId);
    await list.save();

    // Remover todas as vendas relacionadas a esse produto
    await Sale.deleteMany({ 'products.productId': productId });

    await list.populate('products');
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

// Get specific custom list by ID
app.get('/api/custom-lists/:listId', authenticate, async (req, res) => {
  try {
    const { listId } = req.params;
    const currentUserId = req.user._id;

    // Validate ObjectId format
    if (!listId.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ error: 'Invalid list ID format' });
    }

    const list = await CustomList.findById(listId).populate('products');
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

    res.json(list);
  } catch (error) {
    console.error('Error fetching custom list:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid list ID format' });
    }
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
                name: '$$product.productDetails.name',
                quantity: '$$product.quantity',
                price: { $toDouble: '$$product.productDetails.price' }
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

// Test endpoint to check if server is running
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Backend is running!', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
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
            <strong>🌐 CORS Configurado:</strong> A API aceita requisições dos domínios localhost:3000,localhost:3005 ,https://www.jhorello.com.br e https://frontend-lis.vercel.app com os métodos GET, POST, PUT, DELETE e OPTIONS.
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
      return res.status(400).json({ error: 'File size must be less than 5MB' });
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

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api`);
  console.log(`🌐 CORS enabled for development`);
});