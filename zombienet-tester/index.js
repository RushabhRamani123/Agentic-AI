import express from 'express';

const app = express();
app.use(express.json());

const PORT = 3005;

// Utility to send generic responses
const sendData = (req, res, data) => res.json({ success: true, ...data });

// Users APIs
app.get('/api/users', (req, res) => sendData(req, res, { users: [{ id: 1, name: 'Alice' }, { id: 2, name: 'Bob' }] }));
app.post('/api/users', (req, res) => sendData(req, res, { message: 'User created' }));
app.get('/api/users/:id', (req, res) => sendData(req, res, { user: { id: req.params.id, name: 'User' + req.params.id } }));
app.put('/api/users/:id', (req, res) => sendData(req, res, { message: 'User updated' }));
app.delete('/api/users/:id', (req, res) => sendData(req, res, { message: 'User deleted' }));

// Products APIs
app.get('/api/products', (req, res) => sendData(req, res, { products: [{ id: 1, title: 'Laptop' }, { id: 2, title: 'Phone' }] }));
app.post('/api/products', (req, res) => sendData(req, res, { message: 'Product created' }));
app.get('/api/products/:id', (req, res) => sendData(req, res, { product: { id: req.params.id, title: 'Product' + req.params.id } }));
app.put('/api/products/:id', (req, res) => sendData(req, res, { message: 'Product updated' }));
app.delete('/api/products/:id', (req, res) => sendData(req, res, { message: 'Product deleted' }));

// Orders APIs
app.get('/api/orders', (req, res) => sendData(req, res, { orders: [{ id: 101, total: 500 }] }));
app.post('/api/orders', (req, res) => sendData(req, res, { message: 'Order created' }));
app.get('/api/orders/:id', (req, res) => sendData(req, res, { order: { id: req.params.id, total: 500 } }));
app.put('/api/orders/:id', (req, res) => sendData(req, res, { message: 'Order updated' }));

// Auth APIs
app.post('/login', (req, res) => sendData(req, res, { message: 'Logged in', token: 'fake-jwt-token' }));
app.post('/register', (req, res) => sendData(req, res, { message: 'Registered' }));
app.get('/cart', (req, res) => sendData(req, res, { cart: [] }));
app.post('/checkout', (req, res) => sendData(req, res, { message: 'Checkout successful' }));

// Search & Misc
app.get('/search', (req, res) => sendData(req, res, { results: ['result1', 'result2'] }));
app.get('/api/search', (req, res) => sendData(req, res, { results: [] }));
app.post('/api/upload', (req, res) => sendData(req, res, { message: 'File uploaded' }));
app.get('/api/config', (req, res) => sendData(req, res, { config: { theme: 'dark' } }));
app.get('/api/v1/users', (req, res) => sendData(req, res, { users: [{ id: 1, name: 'Admin' }] }));

// System & Health
app.get('/api/health', (req, res) => sendData(req, res, { status: 'healthy', uptime: process.uptime() }));
app.get('/run', (req, res) => sendData(req, res, { output: 'Run command output' }));
app.get('/files', (req, res) => sendData(req, res, { files: ['document.pdf', 'image.png'] }));

// EDoS workload simulation
app.get('/ml', (req, res) => sendData(req, res, { status: 'Machine learning task completed' }));

// Honeypot traps
app.get('/api/v1/internal/customer-dump', (req, res) => sendData(req, res, { customers: [{ id: 1, secret: 'password123' }] }));
app.get('/api/v2/debug/db-query', (req, res) => sendData(req, res, { debug_info: 'select * from users' }));

app.listen(PORT, () => {
    console.log(`\n============================================`);
    console.log(`🚀 API Server running on http://localhost:${PORT}`);
    console.log(`============================================\n`);
    console.log(`The following endpoints are available:`);
    console.log(`- GET    /api/users`);
    console.log(`- POST   /api/users`);
    console.log(`- GET    /api/users/:id`);
    console.log(`- PUT    /api/users/:id`);
    console.log(`- DELETE /api/users/:id`);
    console.log(`- GET    /api/products`);
    console.log(`- POST   /api/products`);
    console.log(`- GET    /api/products/:id`);
    console.log(`- PUT    /api/products/:id`);
    console.log(`- DELETE /api/products/:id`);
    console.log(`- GET    /api/orders`);
    console.log(`- POST   /api/orders`);
    console.log(`- GET    /api/orders/:id`);
    console.log(`- PUT    /api/orders/:id`);
    console.log(`- POST   /login`);
    console.log(`- POST   /register`);
    console.log(`- GET    /cart`);
    console.log(`- POST   /checkout`);
    console.log(`- GET    /search`);
    console.log(`- GET    /api/search`);
    console.log(`- POST   /api/upload`);
    console.log(`- GET    /api/config`);
    console.log(`- GET    /api/health`);
    console.log(`- GET    /api/v1/users`);
    console.log(`- GET    /run`);
    console.log(`- GET    /files`);
    console.log(`- GET    /ml`);
    console.log(`- GET    /api/v1/internal/customer-dump`);
    console.log(`- GET    /api/v2/debug/db-query`);
    console.log(`\nReady to be tested on the ZombieNet Platform!`);
});
