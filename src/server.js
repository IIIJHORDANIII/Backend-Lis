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
const { uploadToS3 } = require('./services/s3Service');
const bcrypt = require('bcryptjs');
const DraftSale = require('./models/DraftSale');
const router = express.Router();

// Log environment variables (remove in production)
console.log('MongoDB URI:', process.env.MONGODB_URI ? 'URI is set' : 'URI is not set');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ["http://localhost:3000", "http://localhost:3005"],
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors({
  origin: ["http://localhost:3000", "http://localhost:3005"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors({
  origin: ["http://localhost:3000", "http://localhost:3005"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB Atlas');
}).catch((error) => {
  console.error('MongoDB connection error:', error);
});

// Socket.IO authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, 'your-secret-key', (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = decoded;
    next();
  });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.user);

  socket.on('disconnect', () => {
    console.log('User disconnected');
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
    const user = new User({ name, email, cpf, password });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        _id: user._id,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error during login' });
  }
});

// Product routes
app.post('/api/products', upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, quantity } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Image is required' });
    }

    // Upload image to S3
    const imageUrl = await uploadToS3(req.file);
    console.log('Image uploaded to S3:', imageUrl);

    const product = new Product({
      name,
      description,
      price,
      quantity: parseInt(quantity) || 0,
      image: imageUrl // Store S3 URL directly
    });
    
    await product.save();
    console.log('Product saved with image URL:', imageUrl);
    
    io.emit('productCreated', product);
    res.status(201).json(product);
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(400).json({ error: error.message });
  }
});

// Add PUT route for updating products
app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, quantity } = req.body;

    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Update product fields
    product.name = name;
    product.description = description;
    product.price = price;
    product.quantity = parseInt(quantity) || 0;

    await product.save();
    console.log('Product updated:', product);

    res.json(product);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/products', authenticate, async (req, res) => {
  try {
    console.log('Fetching products for user:', req.user);
    
    if (req.user.isAdmin) {
      // Admins can see all products
    const products = await Product.find();
      console.log('Admin found all products:', products);
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

    console.log('Regular user found products:', products);
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
    console.log('Debug - Product Data:', JSON.stringify(productData, null, 2));
    res.json(productData);
  } catch (error) {
    console.error('Debug - Error fetching products:', error);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  try {
    console.log('Delete request received:', {
      params: req.params,
      headers: req.headers,
      user: req.user
    });

    // Check if user is admin
    if (!req.user.isAdmin) {
      console.log('User is not admin:', req.user);
      return res.status(403).json({ error: 'Only admins can delete products' });
    }

    const product = await Product.findById(req.params.id);
    
    if (!product) {
      console.log('Product not found:', req.params.id);
      return res.status(404).json({ error: 'Product not found' });
    }

    await product.deleteOne();
    console.log('Product deleted successfully:', req.params.id);
    
    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(400).json({ error: error.message });
  }
});

// Custom Lists routes
app.post('/api/custom-lists', authenticate, async (req, res) => {
  try {
    console.log('Creating custom list with data:', req.body);
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
    console.log('Custom list created successfully:', customList);
    res.status(201).json(customList);
  } catch (error) {
    console.error('Error creating custom list:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/custom-lists', authenticate, async (req, res) => {
  try {
    console.log('Fetching custom lists for user:', req.user._id);
    
    if (req.user.isAdmin) {
      // Admins can see all lists
      const lists = await CustomList.find().populate('products');
      console.log('Admin found all lists:', lists);
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

    console.log('Regular user found their lists:', lists);
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
      console.log('Admin user created successfully');
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
    const sales = await Sale.find(query)
      .populate('products.productId')
      .sort({ createdAt: -1 });
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

    console.log('Criando venda:', {
      userId: req.user._id,
      products,
      total,
      commission
    });

    const sale = new Sale({
      userId: req.user._id,
      products,
      total,
      commission
    });

    await sale.save();
    console.log('Venda criada com sucesso:', sale);

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

    console.log('Buscando resumo de vendas...');
    
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

    console.log('Vendas encontradas:', JSON.stringify(sales, null, 2));
    res.json(sales);
  } catch (error) {
    console.error('Erro ao buscar resumo de vendas:', error);
    res.status(500).json({ message: 'Erro ao buscar resumo de vendas' });
  }
});

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rota para obter resumo de vendas (apenas admin)
router.get('/sales/summary', authenticateToken, async (req, res) => {
  try {
    // Verificar se o usuário é admin
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    console.log('Buscando resumo de vendas...');

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
                price: '$$product.productDetails.price'
              }
            }
          },
          total: 1,
          commission: 1,
          createdAt: 1
        }
      },
      {
        $sort: { createdAt: -1 }
      }
    ]);

    console.log(`Total de vendas encontradas: ${sales.length}`);
    console.log('Primeira venda:', sales[0]);

    res.json(sales);
  } catch (error) {
    console.error('Erro ao buscar resumo de vendas:', error);
    res.status(500).json({ message: 'Erro ao buscar resumo de vendas' });
  }
});

// Rota para criar uma nova venda
router.post('/sales', authenticateToken, async (req, res) => {
  try {
    const { products, total, commission } = req.body;
    const userId = req.user.id;

    // Validar dados
    if (!products || !Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ message: 'Lista de produtos inválida' });
    }

    if (typeof total !== 'number' || total < 0) {
      return res.status(400).json({ message: 'Valor total inválido' });
    }

    if (typeof commission !== 'number' || commission < 0) {
      return res.status(400).json({ message: 'Valor da comissão inválido' });
    }

    // Criar a venda
    const sale = new Sale({
      userId,
      products,
      total,
      commission
    });

    await sale.save();
    console.log('Venda registrada com sucesso:', sale);

    res.status(201).json(sale);
  } catch (error) {
    console.error('Erro ao registrar venda:', error);
    res.status(500).json({ message: 'Erro ao registrar venda' });
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

module.exports = router;

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  createAdminUser();
});