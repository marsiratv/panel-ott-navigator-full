bash <(cat << 'ENDINSTALL'
#!/bin/bash
set -e

clear
echo "╔════════════════════════════════════════════╗"
echo "║   OTT Navigator - Complete Installation   ║"
echo "║   With Login/Logout System                ║"
echo "╚════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Run as root"
    exit 1
fi

echo "📦 [1/9] Updating system..."
apt update -qq && apt upgrade -y -qq

echo "📦 [2/9] Installing Node.js 18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >/dev/null 2>&1
apt install -y nodejs

echo "📦 [3/9] Installing MySQL..."
export DEBIAN_FRONTEND=noninteractive
apt install -y mysql-server
systemctl start mysql
systemctl enable mysql

DB_PASS="OttPanel2024"
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_PASS}';" 2>/dev/null
mysql -u root -p${DB_PASS} -e "CREATE DATABASE IF NOT EXISTS ott_panel;" 2>/dev/null
mysql -u root -p${DB_PASS} -e "FLUSH PRIVILEGES;" 2>/dev/null

echo "📦 [4/9] Installing Nginx..."
apt install -y nginx
systemctl start nginx
systemctl enable nginx

echo "📦 [5/9] Installing PM2..."
npm install -g pm2

echo "📦 [6/9] Creating application structure..."
mkdir -p /var/www/ott-panel/public
cd /var/www/ott-panel

cat > package.json << 'EOF'
{
  "name": "ott-panel",
  "version": "1.0.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "mysql2": "^3.6.5",
    "express-rate-limit": "^7.1.5",
    "dotenv": "^16.3.1"
  }
}
EOF

npm install

cat > .env << ENV
PORT=3000
JWT_SECRET=$(openssl rand -hex 32)
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=${DB_PASS}
DB_NAME=ott_panel
ENV

echo "📦 [7/9] Creating backend server..."

cat > server.js << 'SERVERCODE'
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Initialize database
async function initDatabase() {
  try {
    const conn = await pool.getConnection();
    
    // Create tables
    await conn.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100),
        password VARCHAR(255) NOT NULL,
        package VARCHAR(100),
        status VARCHAR(20) DEFAULT 'active',
        expiry_date DATE,
        max_connections INT DEFAULT 1,
        revenue DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(100) NOT NULL,
        duration VARCHAR(50),
        price DECIMAL(10,2),
        connections INT DEFAULT 1,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS channels (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(100) NOT NULL,
        category VARCHAR(50),
        stream_url TEXT NOT NULL,
        logo_url TEXT,
        epg_id VARCHAR(50),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create default admin
    const [admins] = await conn.query('SELECT * FROM admins LIMIT 1');
    if (admins.length === 0) {
      const hash = await bcrypt.hash('admin123', 10);
      await conn.query(
        'INSERT INTO admins (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@ott.com', hash, 'superadmin']
      );
      console.log('✓ Default admin created: admin / admin123');
    }

    conn.release();
    console.log('✓ Database initialized');
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  }
}

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [admins] = await pool.query(
      'SELECT * FROM admins WHERE username = ? OR email = ?',
      [username, username]
    );

    if (admins.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = admins[0];
    const validPassword = await bcrypt.compare(password, admin.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ==================== USER ROUTES ====================

app.get('/api/users', authenticate, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticate, async (req, res) => {
  try {
    const { username, email, password, package: pkg, expiry_date, max_connections, revenue } = req.body;
    const hash = await bcrypt.hash(password, 10);
    
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password, package, expiry_date, max_connections, revenue) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [username, email, hash, pkg, expiry_date, max_connections, revenue || 0]
    );

    res.json({ id: result.insertId, message: 'User created successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create user' });
    }
  }
});

app.put('/api/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, package: pkg, status, expiry_date, max_connections, revenue } = req.body;
    
    await pool.query(
      'UPDATE users SET username=?, email=?, package=?, status=?, expiry_date=?, max_connections=?, revenue=? WHERE id=?',
      [username, email, pkg, status, expiry_date, max_connections, revenue, id]
    );

    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/users/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ==================== PACKAGE ROUTES ====================

app.get('/api/packages', authenticate, async (req, res) => {
  try {
    const [packages] = await pool.query('SELECT * FROM packages ORDER BY price');
    res.json(packages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch packages' });
  }
});

app.post('/api/packages', authenticate, async (req, res) => {
  try {
    const { name, duration, price, connections, description } = req.body;
    const [result] = await pool.query(
      'INSERT INTO packages (name, duration, price, connections, description) VALUES (?, ?, ?, ?, ?)',
      [name, duration, price, connections, description]
    );
    res.json({ id: result.insertId, message: 'Package created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create package' });
  }
});

app.delete('/api/packages/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM packages WHERE id = ?', [req.params.id]);
    res.json({ message: 'Package deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete package' });
  }
});

// ==================== CHANNEL ROUTES ====================

app.get('/api/channels', authenticate, async (req, res) => {
  try {
    const [channels] = await pool.query('SELECT * FROM channels WHERE is_active = TRUE');
    res.json(channels);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch channels' });
  }
});

app.post('/api/channels', authenticate, async (req, res) => {
  try {
    const { name, category, stream_url, logo_url, epg_id } = req.body;
    const [result] = await pool.query(
      'INSERT INTO channels (name, category, stream_url, logo_url, epg_id) VALUES (?, ?, ?, ?, ?)',
      [name, category, stream_url, logo_url, epg_id]
    );
    res.json({ id: result.insertId, message: 'Channel created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create channel' });
  }
});

app.delete('/api/channels/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM channels WHERE id = ?', [req.params.id]);
    res.json({ message: 'Channel deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete channel' });
  }
});

// ==================== STATISTICS ====================

app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const [total] = await pool.query('SELECT COUNT(*) as count FROM users');
    const [active] = await pool.query('SELECT COUNT(*) as count FROM users WHERE status = "active"');
    const [revenue] = await pool.query('SELECT SUM(revenue) as total FROM users');
    const [today] = await pool.query('SELECT COUNT(*) as count FROM users WHERE DATE(created_at) = CURDATE()');
    const [monthly] = await pool.query('SELECT COUNT(*) as count FROM users WHERE MONTH(created_at) = MONTH(CURDATE())');

    res.json({
      totalUsers: total[0].count,
      activeUsers: active[0].count,
      totalRevenue: revenue[0].total || 0,
      todayCreated: today[0].count,
      monthlyCreated: monthly[0].count
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ==================== M3U PLAYLIST ====================

app.get('/api/playlist/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0 || users[0].status !== 'active') {
      return res.status(404).send('User not found or inactive');
    }

    const [channels] = await pool.query('SELECT * FROM channels WHERE is_active = TRUE');
    
    let m3u = '#EXTM3U\n';
    channels.forEach(ch => {
      m3u += `#EXTINF:-1 tvg-id="${ch.epg_id || ''}" tvg-logo="${ch.logo_url || ''}" group-title="${ch.category}",${ch.name}\n${ch.stream_url}\n`;
    });

    res.setHeader('Content-Type', 'audio/x-mpegurl');
    res.setHeader('Content-Disposition', `attachment; filename="${username}.m3u"`);
    res.send(m3u);
  } catch (error) {
    res.status(500).send('Error generating playlist');
  }
});

// ==================== XTREAM CODES API ====================

app.get('/player_api.php', async (req, res) => {
  try {
    const { username, password, action } = req.query;
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const valid = await bcrypt.compare(password, user.password);
    
    if (!valid) {
      return res.json({ error: 'Invalid credentials' });
    }

    if (action === 'get_live_streams') {
      const [channels] = await pool.query('SELECT * FROM channels WHERE is_active = TRUE');
      res.json(channels.map(ch => ({
        num: ch.id,
        name: ch.name,
        stream_id: ch.id,
        stream_icon: ch.logo_url,
        epg_channel_id: ch.epg_id,
        category_id: 1
      })));
    } else {
      res.json({
        user_info: {
          username: user.username,
          status: user.status === 'active' ? 'Active' : 'Banned',
          exp_date: new Date(user.expiry_date).getTime() / 1000,
          max_connections: user.max_connections
        },
        server_info: {
          url: req.protocol + '://' + req.get('host')
        }
      });
    }
  } catch (error) {
    res.json({ error: 'API error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    server: '31.97.190.61',
    timestamp: new Date().toISOString()
  });
});

// Serve dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
const PORT = process.env.PORT || 3000;

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║   ✅ OTT Navigator Panel Started      ║
║                                        ║
║   Port: ${PORT}                          ║
║   Server: http://31.97.190.61          ║
║                                        ║
║   Login: admin / admin123              ║
╚════════════════════════════════════════╝
    `);
  });
}).catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
SERVERCODE

echo "📦 [8/9] Creating frontend files..."

# Create Login Page
cat > public/login.html << 'LOGINHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - OTT Navigator Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full">
        <div class="bg-gray-800 rounded-lg shadow-2xl p-8">
            <div class="text-center mb-8">
                <h1 class="text-3xl font-bold text-white mb-2">OTT Navigator</h1>
                <p class="text-gray-400">Admin Panel Login</p>
            </div>
            
            <form id="loginForm" class="space-y-6">
                <div>
                    <label class="block text-gray-300 mb-2 text-sm font-medium">Username</label>
                    <input 
                        type="text" 
                        id="username" 
                        value="admin"
                        class="w-full bg-gray-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter username"
                        required
                    >
                </div>
                
                <div>
                    <label class="block text-gray-300 mb-2 text-sm font-medium">Password</label>
                    <input 
                        type="password" 
                        id="password" 
                        value="admin123"
                        class="w-full bg-gray-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter password"
                        required
                    >
                </div>
                
                <div id="errorMessage" class="hidden bg-red-500/10 border border-red-500 text-red-500 px-4 py-3 rounded-lg text-sm">
                </div>
                
                <button 
                    type="submit" 
                    id="loginBtn"
                    class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition-colors"
                >
                    Login
                </button>
            </form>
            
            <div class="mt-6 text-center">
                <p class="text-gray-400 text-sm">Server: 31.97.190.61</p>
            </div>
        </div>
        
        <p class="text-center text-gray-500 text-sm mt-6">
            OTT Navigator Panel v1.0
        </p>
    </div>
    
    <script>
        const API_URL = window.location.origin + '/api';
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('errorMessage');
            const loginBtn = document.getElementById('loginBtn');
            
            // Disable button
            loginBtn.disabled = true;
            loginBtn.textContent = 'Logging in...';
            
            try {
                const response = await fetch(API_URL + '/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Save token and user data
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    
                    // Redirect to dashboard
                    window.location.href = '/dashboard.html';
                } else {
                    errorDiv.textContent = data.error || 'Login failed';
                    errorDiv.classList.remove('hidden');
                    loginBtn.disabled = false;
                    loginBtn.textContent = 'Login';
                }
            } catch (error) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.classList.remove('hidden');
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
            }
        });
    </script>
</body>
</html>
LOGINHTML

# Create Main Dashboard
cat > public/dashboard.html << 'DASHBOARDHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTT Navigator - Admin Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900">
    <div id="app"></div>
    
    <script>
        const API_URL = window.location.origin + '/api';
        
        // Check authentication
        const token = localStorage.getItem('token');
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        
        if (!token) {
            window.location.href = '/login.html';
        }
        
        // Verify token
        fetch(API_URL + '/auth/verify', {
            headers: { 'Authorization': 'Bearer ' + token }
        }).then(res => {
            if (!res.ok) {
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                window.location.href = '/login.html';
            }
        });
        
        // Logout function
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                fetch(API_URL + '/auth/logout', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token }
                }).finally(() => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.href = '/login.html';
                });
            }
        }
        
        // State management
        let currentPage = 'dashboard';
        let stats = {};
        let users = [];
        let packages = [];
        let channels = [];
        let loading = false;
        
        // Fetch data
        async function fetchData() {
            loading = true;
            render();
            
            try {
                const headers = { 'Authorization': 'Bearer ' + token };
                
                const [statsRes, usersRes, packagesRes, channelsRes] = await Promise.all([
                    fetch(API_URL + '/stats', { headers }),
                    fetch(API_URL + '/users', { headers }),
                    fetch(API_URL + '/packages', { headers }),
                    fetch(API_URL + '/channels', { headers })
                ]);
                
                stats = await statsRes.json();
                users = await usersRes.json();
                packages = await packagesRes.json();
                channels = await channelsRes.json();
            } catch (error) {
                console.error('Error fetching data:', error);
            }
            
            loading = false;
            render();
        }
        
        // Render function
        function render() {
            const app = document.getElementById('app');
            
            app.innerHTML = `
                <div class="min-h-screen bg-gray-900">
                    <!-- Header -->
                    <div class="bg-gray-800 border-b border-gray-700 px-4 py-4">
                        <div class="flex justify-between items-center">
                            <h1 class="text-2xl font-bold text-white">OTT Navigator Panel</h1>
                            <div class="flex items-center gap-4">
                                <div class="text-right hidden md:block">
                                    <p class="text-sm text-gray-400">Logged in as</p>
                                    <p class="text-white font-semibold">${user.username}</p>
                                </div>
                                <button onclick="logout()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg">
                                    Logout
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Navigation -->
                    <div class="bg-gray-800 border-b border-gray-700 px-4 overflow-x-auto">
                        <div class="flex gap-2 py-2">
                            <button onclick="changePage('dashboard')" class="${currentPage === 'dashboard' ? 'bg-blue-600' : 'bg-gray-700'} text-white px-4 py-2 rounded-lg whitespace-nowrap">
                                Dashboard
                            </button>
                            <button onclick="changePage('users')" class="${currentPage === 'users' ? 'bg-blue-600' : 'bg-gray-700'} text-white px-4 py-2 rounded-lg whitespace-nowrap">
                                Users (${users.length})
                            </button>
                            <button onclick="changePage('packages')" class="${currentPage === 'packages' ? 'bg-blue-600' : 'bg-gray-700'} text-white px-4 py-2 rounded-lg whitespace-nowrap">
                                Packages (${packages.length})
                            </button>
                            <button onclick="changePage('channels')" class="${currentPage === 'channels' ? 'bg-blue-600' : 'bg-gray-700'} text-white px-4 py-2 rounded-lg whitespace-nowrap">
                                Channels (${channels.length})
                            </button>
                        </div>
                    </div>
                    
                    <!-- Content -->
                    <div class="p-4">
                        ${loading ? '<div class="text-white text-center py-20">Loading...</div>' : renderContent()}
                    </div>
                </div>
            `;
        }
        
        function renderContent() {
            switch(currentPage) {
                case 'dashboard':
                    return renderDashboard();
                case 'users':
                    return renderUsers();
                case 'packages':
                    return renderPackages();
                case 'channels':
                    return renderChannels();
                default:
                    return '<div class="text-white">Page not found</div>';
            }
        }
        
        function renderDashboard() {
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold text-white">Dashboard Overview</h2>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div class="bg-blue-600 rounded-lg p-6 text-white">
                            <p class="text-sm opacity-90">Total Users</p>
                            <p class="text-3xl font-bold mt-2">${stats.totalUsers || 0}</p>
                            <p class="text-xs opacity-75 mt-1">${stats.activeUsers || 0} active</p>
                        </div>
                        
                        <div class="bg-green-600 rounded-lg p-6 text-white">
                            <p class="text-sm opacity-90">Today Created</p>
                            <p class="text-3xl font-bold mt-2">${stats.todayCreated || 0}</p>
                            <p class="text-xs opacity-75 mt-1">New registrations</p>
                        </div>
                        
                        <div class="bg-purple-600 rounded-lg p-6 text-white">
                            <p class="text-sm opacity-90">This Month</p>
                            <p class="text-3xl font-bold mt-2">${stats.monthlyCreated || 0}</p>
                            <p class="text-xs opacity-75 mt-1">Monthly growth</p>
                        </div>
                        
                        <div class="bg-orange-600 rounded-lg p-6 text-white">
                            <p class="text-sm opacity-90">Total Revenue</p>
                            <p class="text-3xl font-bold mt-2">RM ${(stats.totalRevenue || 0).toFixed(2)}</p>
                            <p class="text-xs opacity-75 mt-1">Earnings</p>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div class="bg-gray-800 rounded-lg p-6">
                            <h3 class="text-lg font-semibold text-white mb-4">Quick Stats</h3>
                            <div class="space-y-3 text-gray-300">
                                <div class="flex justify-between">
                                    <span>Total Users:</span>
                                    <span class="font-semibold text-blue-400">${users.length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>Active Users:</span>
                                    <span class="font-semibold text-green-400">${users.filter(u => u.status === 'active').length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>Expired Users:</span>
                                    <span class="font-semibold text-red-400">${users.filter(u => u.status === 'expired').length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>Total Packages:</span>
                                    <span class="font-semibold text-yellow-400">${packages.length}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span>Total Channels:</span>
                                    <span class="font-semibold text-pink-400">${channels.length}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="bg-gray-800 rounded-lg p-6">
                            <h3 class="text-lg font-semibold text-white mb-4">Recent Users</h3>
                            <div class="space-y-2">
                                ${users.slice(0, 5).map(u => `
                                    <div class="flex justify-between items-center text-sm border-b border-gray-700 pb-2">
                                        <div>
                                            <div class="text-white">${u.username}</div>
                                            <div class="text-xs text-gray-400">${u.email || 'No email'}</div>
                                        </div>
                                        <span class="px-2 py-1 rounded text-xs ${u.status === 'active' ? 'bg-green-600' : 'bg-red-600'}">
                                            ${u.status}
                                        </span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        function renderUsers() {
            return `
                <div class="space-y-4">
                    <div class="flex justify-between items-center flex-wrap gap-4">
                        <h2 class="text-2xl font-bold text-white">Users Management (${users.length})</h2>
                        <button onclick="showUserForm()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg">
                            + Add User
                        </button>
                    </div>
                    
                    <div class="bg-gray-800 rounded-lg overflow-hidden">
                        <div class="overflow-x-auto">
                            <table class="w-full">
                                <thead class="bg-gray-700">
                                    <tr>
                                        <th class="px-4 py-3 text-left text-white">Username</th>
                                        <th class="px-4 py-3 text-left text-white hidden md:table-cell">Email</th>
                                        <th class="px-4 py-3 text-left text-white">Package</th>
                                        <th class="px-4 py-3 text-left text-white">Status</th>
                                        <th class="px-4 py-3 text-left text-white">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${users.map(u => `
                                        <tr class="border-b border-gray-700">
                                            <td class="px-4 py-3 text-gray-300">${u.username}</td>
                                            <td class="px-4 py-3 text-gray-300 hidden md:table-cell">${u.email || 'N/A'}</td>
                                            <td class="px-4 py-3 text-gray-300">${u.package || 'None'}</td>
                                            <td class="px-4 py-3">
                                                <span class="px-2 py-1 rounded text-xs ${u.status === 'active' ? 'bg-green-600' : 'bg-red-600'}">
                                                    ${u.status}
                                                </span>
                                            </td>
                                            <td class="px-4 py-3">
                                                <div class="flex gap-2">
                                                    <button onclick="downloadM3U('${u.username}')" class="text-green-400 hover:text-green-300" title="Download M3U">
                                                        📥
                                                    </button>
                                                    <button onclick="deleteUser(${u.id})" class="text-red-400 hover:text-red-300" title="Delete">
                                                        🗑️
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }
        
        function renderPackages() {
            return `
                <div class="space-y-4">
                    <div class="flex justify-between items-center">
                        <h2 class="text-2xl font-bold text-white">Packages Management</h2>
                        <button onclick="showPackageForm()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg">
                            + Add Package
                        </button>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        ${packages.map(pkg => `
                            <div class="bg-gray-800 rounded-lg p-6 relative">
                                <button onclick="deletePackage(${pkg.id})" class="absolute top-4 right-4 text-red-400 hover:text-red-300">
                                    🗑️
                                </button>
                                <h3 class="text-xl font-bold text-white mb-2">${pkg.name}</h3>
                                <p class="text-gray-400 mb-4 text-sm">${pkg.description || 'No description'}</p>
                                <div class="space-y-2 text-gray-300 text-sm">
                                    <div class="flex justify-between">
                                        <span>Duration:</span>
                                        <span class="font-semibold">${pkg.duration}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span>Price:</span>
                                        <span class="font-semibold text-green-400">RM ${pkg.price}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span>Connections:</span>
                                        <span class="font-semibold">${pkg.connections}</span>
                                    </div>
                                    <div class="flex justify-between pt-2 border-t border-gray-700">
                                        <span>Users:</span>
                                        <span class="font-semibold text-blue-400">
                                            ${users.filter(u => u.package === pkg.name).length}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        function renderChannels() {
            return `
                <div class="space-y-4">
                    <div class="flex justify-between items-center">
                        <h2 class="text-2xl font-bold text-white">Channels (${channels.length})</h2>
                        <button onclick="showChannelForm()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg">
                            + Add Channel
                        </button>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                        ${channels.map(ch => `
                            <div class="bg-gray-800 rounded-lg p-4">
                                <div class="flex items-start justify-between mb-2">
                                    <div class="flex-1">
                                        <h3 class="text-white font-semibold mb-1">${ch.name}</h3>
                                        <span class="text-xs px-2 py-1 rounded bg-blue-600">${ch.category}</span>
                                    </div>
                                    <button onclick="deleteChannel(${ch.id})" class="text-red-400 hover:text-red-300">
                                        🗑️
                                    </button>
                                </div>
                                ${ch.logo_url ? `<img src="${ch.logo_url}" class="w-full h-20 object-cover rounded mt-2" onerror="this.style.display='none'">` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        // Helper functions
        function changePage(page) {
            currentPage = page;
            render();
        }
        
        function downloadM3U(username) {
            window.open(API_URL.replace('/api', '') + `/api/playlist/${username}`, '_blank');
        }
        
        async function deleteUser(id) {
            if (!confirm('Delete this user?')) return;
            
            try {
                const res = await fetch(API_URL + '/users/' + id, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                
                if (res.ok) {
                    alert('User deleted!');
                    fetchData();
                }
            } catch (error) {
                alert('Error deleting user');
            }
        }
        
        async function deletePackage(id) {
            if (!confirm('Delete this package?')) return;
            
            try {
                const res = await fetch(API_URL + '/packages/' + id, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                
                if (res.ok) {
                    alert('Package deleted!');
                    fetchData();
                }
            } catch (error) {
                alert('Error deleting package');
            }
        }
        
        async function deleteChannel(id) {
            if (!confirm('Delete this channel?')) return;
            
            try {
                const res = await fetch(API_URL + '/channels/' + id, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                
                if (res.ok) {
                    alert('Channel deleted!');
                    fetchData();
                }
            } catch (error) {
                alert('Error deleting channel');
            }
        }
        
        function showUserForm() {
            const username = prompt('Username:');
            if (!username) return;
            
            const email = prompt('Email:');
            const password = prompt('Password:');
            const packageName = prompt('Package:');
            const expiryDate = prompt('Expiry Date (YYYY-MM-DD):');
            
            if (username && password) {
                fetch(API_URL + '/users', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username,
                        email: email || '',
                        password,
                        package: packageName || '',
                        expiry_date: expiryDate || '2025-12-31',
                        max_connections: 1,
                        revenue: 0
                    })
                }).then(res => res.json())
                .then(data => {
                    if (data.error) {
                        alert('Error: ' + data.error);
                    } else {
                        alert('User created!');
                        fetchData();
                    }
                });
            }
        }
        
        function showPackageForm() {
            const name = prompt('Package Name:');
            if (!name) return;
            
            const duration = prompt('Duration (e.g., 1 Month):');
            const price = prompt('Price (RM):');
            const connections = prompt('Max Connections:');
            const description = prompt('Description:');
            
            if (name && duration && price) {
                fetch(API_URL + '/packages', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name,
                        duration,
                        price: parseFloat(price),
                        connections: parseInt(connections) || 1,
                        description: description || ''
                    })
                }).then(res => res.json())
                .then(data => {
                    if (data.error) {
                        alert('Error: ' + data.error);
                    } else {
                        alert('Package created!');
                        fetchData();
                    }
                });
            }
        }
        
        function showChannelForm() {
            const name = prompt('Channel Name:');
            if (!name) return;
            
            const category = prompt('Category (Sports, Movies, News, etc):');
            const streamUrl = prompt('Stream URL:');
            const logoUrl = prompt('Logo URL (optional):');
            const epgId = prompt('EPG ID (optional):');
            
            if (name && streamUrl) {
                fetch(API_URL + '/channels', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name,
                        category: category || 'General',
                        stream_url: streamUrl,
                        logo_url: logoUrl || '',
                        epg_id: epgId || ''
                    })
                }).then(res => res.json())
                .then(data => {
                    if (data.error) {
                        alert('Error: ' + data.error);
                    } else {
                        alert('Channel added!');
                        fetchData();
                    }
                });
            }
        }
        
        // Initial render and fetch
        render();
        fetchData();
    </script>
</body>
</html>
DASHBOARDHTML

# Create welcome page
cat > public/index.html << 'INDEXHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTT Navigator Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-2xl w-full bg-gray-800 rounded-lg shadow-2xl p-8">
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-white mb-2">🚀 OTT Navigator Panel</h1>
            <p class="text-gray-400">Server: 31.97.190.61</p>
        </div>
        
        <div class="bg-green-600/10 border border-green-500 rounded-lg p-6 mb-6">
            <h2 class="text-xl font-semibold text-green-400 mb-3">✅ Installation Complete!</h2>
            <div class="text-gray-300 space-y-2 text-sm">
                <p>• Backend API: <span class="text-green-400">Running</span></p>
                <p>• Database: <span class="text-green-400">Connected</span></p>
                <p>• Admin Account: <span class="text-green-400">Ready</span></p>
            </div>
        </div>
        
        <div class="bg-gray-700 rounded-lg p-6 mb-6">
            <h3 class="text-white font-semibold mb-3">🔐 Default Login</h3>
            <div class="space-y-2 text-sm">
                <div class="flex justify-between">
                    <span class="text-gray-400">Username:</span>
                    <span class="text-white font-mono">admin</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">Password:</span>
                    <span class="text-white font-mono">admin123</span>
                </div>
            </div>
        </div>
        
        <div class="space-y-3">
            <a href="/login.html" class="block w-full bg-blue-600 hover:bg-blue-700 text-white text-center font-semibold py-3 rounded-lg transition">
                Login to Panel
            </a>
            <a href="/api/health" target="_blank" class="block w-full bg-gray-700 hover:bg-gray-600 text-white text-center py-3 rounded-lg transition">
                Check API Status
            </a>
        </div>
        
        <div class="mt-6 bg-yellow-600/10 border border-yellow-500 rounded-lg p-4">
            <p class="text-yellow-400 text-sm font-semibold mb-2">⚠️ Security Reminder:</p>
            <p class="text-gray-300 text-xs">Change default password immediately after first login!</p>
        </div>
        
        <p class="text-center text-gray-500 text-xs mt-6">
            OTT Navigator Panel v1.0 | © 2024
        </p>
    </div>
</body>
</html>
INDEXHTML

echo "📦 [9/9] Finalizing installation..."

# Configure Nginx
cat > /etc/nginx/sites-available/ott << 'NGINXCONF'
server {
    listen 80;
    server_name 31.97.190.61 srv1157221.hstgr.cloud;
    
    client_max_body_size 100M;
    
    # Root directory
    root /var/www/ott-panel/public;
    index index.html;
    
    # Static files
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
    
    # Xtream Codes API
    location /player_api.php {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINXCONF

ln -sf /etc/nginx/sites-available/ott /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx config
nginx -t

# Reload Nginx
systemctl reload nginx

# Start application with PM2
cd /var/www/ott-panel
pm2 delete ott-panel 2>/dev/null || true
pm2 start server.js --name ott-panel
pm2 save
pm2 startup systemd -u root --hp /root

# Setup firewall
ufw --force enable
ufw allow 22
ufw allow 80
ufw allow 443

# Set permissions
chown -R www-data:www-data /var/www/ott-panel
chmod -R 755 /var/www/ott-panel

# Save credentials
cat > /var/www/ott-panel/CREDENTIALS.txt << CREDS
═══════════════════════════════════════════════════════
  OTT NAVIGATOR PANEL - INSTALLATION COMPLETE
═══════════════════════════════════════════════════════

🌐 Panel Access:
   URL: http://31.97.190.61
   Dashboard: http://31.97.190.61/dashboard.html
   
🔐 Admin Login:
   Username: admin
   Password: admin123

📊 Database:
   Database: ott_panel
   User: root
   Password: ${DB_PASS}

📁 Installation Directory:
   /var/www/ott-panel

⚙️ Management Commands:
   Status:  pm2 status
   Logs:    pm2 logs ott-panel
   Restart: pm2 restart ott-panel
   Stop:    pm2 stop ott-panel

📝 API Endpoints:
   Health:  http://31.97.190.61/api/health
   Login:   http://31.97.190.61/api/auth/login
   M3U:     http://31.97.190.61/api/playlist/{username}
   Xtream:  http://31.97.190.61/player_api.php

⚠️ IMPORTANT:
   1. Change default admin password immediately
   2. Setup SSL certificate for production
   3. Configure automated backups
   4. Keep this file secure

Installation Date: $(date)
═══════════════════════════════════════════════════════
CREDS

chmod 600 /var/www/ott-panel/CREDENTIALS.txt

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || echo "31.97.190.61")

# Clear screen and show success
clear
echo "╔════════════════════════════════════════════════════════╗"
echo "║                                                        ║"
echo "║          ✅ INSTALLATION COMPLETE!                     ║"
echo "║                                                        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Access URLs:"
echo "   Main:      http://${SERVER_IP}"
echo "   Login:     http://${SERVER_IP}/login.html"
echo "   Dashboard: http://${SERVER_IP}/dashboard.html"
echo ""
echo "🔐 Default Login:"
echo "   Username:  admin"
echo "   Password:  admin123"
echo ""
echo "📊 Management Commands:"
echo "   pm2 status"
echo "   pm2 logs ott-panel"
echo "   pm2 restart ott-panel"
echo ""
echo "📄 Credentials saved at:"
echo "   /var/www/ott-panel/CREDENTIALS.txt"
echo ""
echo "⚠️  IMPORTANT NEXT STEPS:"
echo "   1. Login and change default password"
echo "   2. Create packages and channels"
echo "   3. Setup SSL: certbot --nginx -d yourdomain.com"
echo "   4. Configure automated backups"
echo ""
echo "🎉 Your OTT Navigator Panel is ready!"
echo ""
ENDINSTALL
)
