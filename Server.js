// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

// CORS Configuration - Fixed to handle both with and without trailing slash
const allowedOrigins = [
  'https://appointment-booking-frontend-coral.vercel.app',
  'https://appointment-booking-frontend-beta.vercel.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Remove trailing slash from origin for comparison
    const normalizedOrigin = origin.replace(/\/$/, '');
    
    if (allowedOrigins.some(allowed => allowed === normalizedOrigin)) {
      return callback(null, true);
    } else {
      console.log(`CORS blocked origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/', limiter);

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: { code: 'UNAUTHORIZED', message: 'Access token required' } 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' } 
      });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      error: { code: 'ADMIN_REQUIRED', message: 'Admin access required' } 
    });
  }
  next();
};

// Validation helpers
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  return password && password.length >= 8;
};

// Generate time slots for the next 7 days
const generateSlots = async () => {
  const slots = [];
  const startDate = new Date();
  startDate.setHours(0, 0, 0, 0);

  for (let day = 0; day < 7; day++) {
    const currentDate = new Date(startDate);
    currentDate.setDate(startDate.getDate() + day);
    
    // Generate slots from 9:00 to 17:00 (30-minute intervals)
    for (let hour = 9; hour < 17; hour++) {
      for (let minute = 0; minute < 60; minute += 30) {
        const startAt = new Date(currentDate);
        startAt.setHours(hour, minute, 0, 0);
        
        const endAt = new Date(startAt);
        endAt.setMinutes(startAt.getMinutes() + 30);

        slots.push({ startAt, endAt });
      }
    }
  }

  // Insert slots that don't already exist
  for (const slot of slots) {
    const existing = await prisma.slot.findFirst({
      where: { 
        startAt: slot.startAt,
        endAt: slot.endAt 
      }
    });
    
    if (!existing) {
      await prisma.slot.create({ data: slot });
    }
  }
};

// Seed admin user
const seedAdmin = async () => {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Passw0rd!';
  
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail }
  });

  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await prisma.user.create({
      data: {
        name: 'Admin User',
        email: adminEmail,
        passwordHash,
        role: 'admin'
      }
    });
    console.log(`Admin user seeded: ${adminEmail}`);
  }
};

// Routes
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        error: { code: 'MISSING_FIELDS', message: 'Name, email, and password are required' }
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({
        error: { code: 'INVALID_EMAIL', message: 'Invalid email format' }
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        error: { code: 'WEAK_PASSWORD', message: 'Password must be at least 8 characters' }
      });
    }

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(409).json({
        error: { code: 'EMAIL_EXISTS', message: 'Email already registered' }
      });
    }

    // Create user
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash,
        role: 'patient'
      }
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: { code: 'REGISTRATION_FAILED', message: 'Registration failed' }
    });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: { code: 'MISSING_CREDENTIALS', message: 'Email and password are required' }
      });
    }

    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' }
      });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      role: user.role,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: { code: 'LOGIN_FAILED', message: 'Login failed' }
    });
  }
});

app.get('/slots', async (req, res) => {
  try {
    const { from, to } = req.query;
    
    const whereClause = {};
    if (from) whereClause.startAt = { gte: new Date(from) };
    if (to) whereClause.startAt = { ...whereClause.startAt, lte: new Date(to) };

    const slots = await prisma.slot.findMany({
      where: {
        ...whereClause,
        booking: null // Only available slots
      },
      orderBy: { startAt: 'asc' }
    });

    res.json(slots);
  } catch (error) {
    console.error('Get slots error:', error);
    res.status(500).json({
      error: { code: 'FETCH_SLOTS_FAILED', message: 'Failed to fetch slots' }
    });
  }
});

app.post('/book', authenticateToken, async (req, res) => {
  try {
    const { slotId } = req.body;

    if (!slotId) {
      return res.status(400).json({
        error: { code: 'MISSING_SLOT_ID', message: 'Slot ID is required' }
      });
    }

    // Check if slot exists and is available
    const slot = await prisma.slot.findUnique({
      where: { id: slotId },
      include: { booking: true }
    });

    if (!slot) {
      return res.status(404).json({
        error: { code: 'SLOT_NOT_FOUND', message: 'Slot not found' }
      });
    }

    if (slot.booking) {
      return res.status(409).json({
        error: { code: 'SLOT_TAKEN', message: 'Slot is already booked' }
      });
    }

    // Create booking
    const booking = await prisma.booking.create({
      data: {
        userId: req.user.userId,
        slotId
      },
      include: {
        slot: true,
        user: { select: { id: true, name: true, email: true } }
      }
    });

    res.status(201).json(booking);
  } catch (error) {
    console.error('Booking error:', error);
    if (error.code === 'P2002' && error.meta?.target?.includes('slotId')) {
      return res.status(409).json({
        error: { code: 'SLOT_TAKEN', message: 'Slot is already booked' }
      });
    }
    res.status(500).json({
      error: { code: 'BOOKING_FAILED', message: 'Failed to create booking' }
    });
  }
});

app.get('/my-bookings', authenticateToken, async (req, res) => {
  try {
    const bookings = await prisma.booking.findMany({
      where: { userId: req.user.userId },
      include: { slot: true },
      orderBy: { createdAt: 'desc' }
    });

    res.json(bookings);
  } catch (error) {
    console.error('Get my bookings error:', error);
    res.status(500).json({
      error: { code: 'FETCH_BOOKINGS_FAILED', message: 'Failed to fetch bookings' }
    });
  }
});

app.get('/all-bookings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const bookings = await prisma.booking.findMany({
      include: {
        slot: true,
        user: { select: { id: true, name: true, email: true } }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(bookings);
  } catch (error) {
    console.error('Get all bookings error:', error);
    res.status(500).json({
      error: { code: 'FETCH_ALL_BOOKINGS_FAILED', message: 'Failed to fetch all bookings' }
    });
  }
});

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'Appointment Booking API is running'
  });
});

// Initialize database and start server
const init = async () => {
  try {
    await prisma.$connect();
    console.log('Database connected');
    
    await seedAdmin();
    await generateSlots();
    
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
    });
  } catch (error) {
    console.error('Initialization error:', error);
    process.exit(1);
  }
}
init();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await prisma.$disconnect();
  process.exit();   });