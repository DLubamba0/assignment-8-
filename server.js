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

// Test database connection
async function testConnection() {
  try {
    await db.authenticate();
    console.log('Connection to database established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}

testConnection();

// Authentication middleware
function authMiddleware(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// =========================
// AUTH ROUTES
// =========================

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email, and password are required.'
      });
    }

    const existingUser = await User.findOne({ where: { email } });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword
    });

    res.status(201).json({
      message: 'User registered successfully.',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email
      }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password are required.'
      });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.status(200).json({
      message: 'Login successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error logging out:', err);
      return res.status(500).json({ error: 'Could not log out.' });
    }

    res.status(200).json({ message: 'Logout successful.' });
  });
});

// =========================
// PROJECT ROUTES
// =========================

// GET /api/projects - Get all projects for logged-in user
app.get('/api/projects', authMiddleware, async (req, res) => {
  try {
    const projects = await Project.findAll({
      where: { userId: req.session.userId }
    });
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// GET /api/projects/:id - Get project by ID for logged-in user
app.get('/api/projects/:id', authMiddleware, async (req, res) => {
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

    res.json(project);
  } catch (error) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// POST /api/projects - Create new project for logged-in user
app.post('/api/projects', authMiddleware, async (req, res) => {
  try {
    const { name, description, status, dueDate } = req.body;

    const newProject = await Project.create({
      name,
      description,
      status,
      dueDate,
      userId: req.session.userId
    });

    res.status(201).json(newProject);
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// PUT /api/projects/:id - Update existing project for logged-in user
app.put('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const { name, description, status, dueDate } = req.body;

    const project = await Project.findOne({
      where: {
        id: req.params.id,
        userId: req.session.userId
      }
    });

    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    await project.update({ name, description, status, dueDate });
    res.json(project);
  } catch (error) {
    console.error('Error updating project:', error);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

// DELETE /api/projects/:id - Delete project for logged-in user
app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const deletedRowsCount = await Project.destroy({
      where: {
        id: req.params.id,
        userId: req.session.userId
      }
    });

    if (deletedRowsCount === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

// =========================
// TASK ROUTES
// =========================

// GET /api/tasks - Get all tasks for logged-in user's projects
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
    console.error('Error fetching tasks:', error);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// GET /api/tasks/:id - Get task by ID for logged-in user
app.get('/api/tasks/:id', authMiddleware, async (req, res) => {
  try {
    const task = await Task.findOne({
      where: { id: req.params.id },
      include: [{
        model: Project,
        where: { userId: req.session.userId }
      }]
    });

    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json(task);
  } catch (error) {
    console.error('Error fetching task:', error);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

// POST /api/tasks - Create task only inside user's project
app.post('/api/tasks', authMiddleware, async (req, res) => {
  try {
    const { title, description, completed, priority, dueDate, projectId } = req.body;

    const project = await Project.findOne({
      where: {
        id: projectId,
        userId: req.session.userId
      }
    });

    if (!project) {
      return res.status(404).json({ error: 'Project not found or unauthorized' });
    }

    const newTask = await Task.create({
      title,
      description,
      completed,
      priority,
      dueDate,
      projectId
    });

    res.status(201).json(newTask);
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// PUT /api/tasks/:id - Update task for logged-in user
app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  try {
    const { title, description, completed, priority, dueDate, projectId } = req.body;

    const task = await Task.findOne({
      where: { id: req.params.id },
      include: [{
        model: Project,
        where: { userId: req.session.userId }
      }]
    });

    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    await task.update({
      title,
      description,
      completed,
      priority,
      dueDate,
      projectId
    });

    res.json(task);
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// DELETE /api/tasks/:id - Delete task for logged-in user
app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  try {
    const task = await Task.findOne({
      where: { id: req.params.id },
      include: [{
        model: Project,
        where: { userId: req.session.userId }
      }]
    });

    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    await task.destroy();

    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});