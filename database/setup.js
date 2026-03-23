const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

// Create Sequelize instance
const db = new Sequelize({
  dialect: 'sqlite',
  storage: `database/${process.env.DB_NAME || 'task_management.db'}`,
  logging: console.log
});

// Define User model
const User = db.define('User', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
});

// Define Project model
const Project = db.define('Project', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  status: {
    type: DataTypes.STRING,
    defaultValue: 'active'
  },
  dueDate: {
    type: DataTypes.DATE
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false
  }
});

// Define Task model
const Task = db.define('Task', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  completed: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  priority: {
    type: DataTypes.STRING,
    defaultValue: 'medium'
  },
  dueDate: {
    type: DataTypes.DATE
  },
  projectId: {
    type: DataTypes.INTEGER,
    allowNull: false
  }
});

// Define relationships
User.hasMany(Project, { foreignKey: 'userId' });
Project.belongsTo(User, { foreignKey: 'userId' });

Project.hasMany(Task, { foreignKey: 'projectId' });
Task.belongsTo(Project, { foreignKey: 'projectId' });

// Export for use in other files
module.exports = { db, User, Project, Task };

// Create database and tables
async function setupDatabase() {
  try {
    await db.authenticate();
    console.log('Connection to database established successfully.');

    await db.sync({ force: true });
    console.log('Database and tables created successfully.');

    await db.close();
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}

// Run setup if this file is executed directly
if (require.main === module) {
  setupDatabase();
}