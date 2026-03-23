const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { db, User, Project, Task } = require('./database/setup');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

app.use(session({
  secret: 'mySecretKey',
  resave: false,
  saveUninitialized: false
}));

// Test DB connection
async function testConnection() {
  try {
    await db.authenticate();
    console.log('Connected to database');
  } catch (error) {
    console.error('Database connection failed:', error);
  }
}
testConnection();

// =========================
// AUTH MIDDLEWARE
// =========================
function authMiddleware(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// =========================
// AUTH ROUTES
// =========================

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email, and password are required'
      });
    }

    const existingUser = await User.findOne({ where: { email } });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.session.userId = user.id;

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out successfully' });
  });
});

// =========================
// PROJECT ROUTES (PROTECTED)
// =========================

// GET all projects for logged-in user
app.get('/api/projects', authMiddleware, async (req, res) => {
  try {
    const projects = await Project.findAll({
      where: { userId: req.session.userId }
    });

    res.json(projects);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// CREATE project
app.post('/api/projects', authMiddleware, async (req, res) => {
  try {
    const { name, description, status, dueDate } = req.body;

    const project = await Project.create({
      name,
      description,
      status,
      dueDate,
      userId: req.session.userId
    });

    res.status(201).json(project);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// UPDATE project
app.put('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findOne({
      where: {
        id: req.params.id,
        userId: req.session.userId
      }
    });

    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    await project.update(req.body);

    res.json(project);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

// DELETE project
app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const deleted = await Project.destroy({
      where: {
        id: req.params.id,
        userId: req.session.userId
      }
    });

    if (!deleted) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({ message: 'Project deleted' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

// =========================
// TASK ROUTES (PROTECTED)
// =========================

// GET tasks (only user's projects)
app.get('/api/tasks', authMiddleware, async (req, res) => {
  try {
    const tasks = await Task.findAll({
      include: [{
        model: Project,
        where: { userId: req.session.userId }
      }]
    });

    res.json(tasks);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// CREATE task (only inside user's project)
app.post('/api/tasks', authMiddleware, async (req, res) => {
  try {
    const { projectId } = req.body;

    const project = await Project.findOne({
      where: {
        id: projectId,
        userId: req.session.userId
      }
    });

    if (!project) {
      return res.status(404).json({ error: 'Unauthorized project' });
    }

    const task = await Task.create(req.body);

    res.status(201).json(task);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});