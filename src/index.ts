import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-workers';
import { createHash, randomBytes } from 'crypto';

const app = new Hono();

// Authentication helpers
const hashPassword = (password, salt) => {
  return createHash('sha256').update(password + salt).digest('hex');
};

app.post('/register', async (c) => {
  const { username, password, email, role } = await c.req.json();
  const salt = randomBytes(16).toString('hex');
  const hashedPassword = hashPassword(password, salt);

  await c.env.DB.prepare(
    'INSERT INTO users (username, email, password, salt, role) VALUES (?, ?, ?, ?, ?)'
  ).bind(username, email, hashedPassword, salt, role || 'member').run();

  return c.json({ success: true });
});

app.post('/login', async (c) => {
  const { username, password } = await c.req.json();
  const user = await c.env.DB.prepare(
    'SELECT * FROM users WHERE username = ?'
  ).bind(username).first();

  if (!user || hashPassword(password, user.salt) !== user.password) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const sessionKey = randomBytes(32).toString('hex');
  await c.env.KV.put(`session:${sessionKey}`, user.id, { expirationTtl: 86400 });

  return c.json({ sessionKey });
});

app.use(async (c, next) => {
  const sessionKey = c.req.header('Authorization');
  if (!sessionKey) return c.json({ error: 'Unauthorized' }, 401);
  const userId = await c.env.KV.get(`session:${sessionKey}`);
  if (!userId) return c.json({ error: 'Invalid session' }, 401);
  c.set('userId', userId);
  await next();
});

// User Endpoints
app.post('/users', async (c) => {
  const { name, email, role } = await c.req.json();
  await c.env.DB.prepare('INSERT INTO users (name, email, role) VALUES (?, ?, ?)')
    .bind(name, email, role || 'member')
    .run();
  return c.json({ success: true });
});

app.get('/users', async (c) => {
  const { name, email, role } = c.req.query();
  let query = 'SELECT users.*, COUNT(tasks.id) as completed_tasks, SUM(tasks.cost) as total_cost FROM users LEFT JOIN tasks ON users.id = tasks.assigned_user AND tasks.status = "completed"';
  let conditions = [];
  let bindings = [];
  if (name) {
    conditions.push('users.name LIKE ?');
    bindings.push(`%${name}%`);
  }
  if (email) {
    conditions.push('users.email LIKE ?');
    bindings.push(`%${email}%`);
  }
  if (role) {
    conditions.push('users.role = ?');
    bindings.push(role);
  }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  query += ' GROUP BY users.id';
  const users = await c.env.DB.prepare(query).bind(...bindings).all();
  return c.json(users);
});

// Task Endpoints
app.post('/tasks', async (c) => {
  const { title, description, estimatedHours, dueDate, status, assignedUsers, cost } = await c.req.json();
  await c.env.DB.prepare(
    'INSERT INTO tasks (title, description, estimated_hours, due_date, status, cost) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(title, description, estimatedHours, dueDate, status, cost).run();
  return c.json({ success: true });
});

app.get('/tasks', async (c) => {
  const { dueDate, name, assignedUser, email } = c.req.query();
  let query = 'SELECT * FROM tasks';
  let conditions = [];
  let bindings = [];
  if (dueDate) {
    conditions.push('due_date = ?');
    bindings.push(dueDate);
  }
  if (name) {
    conditions.push('title LIKE ?');
    bindings.push(`%${name}%`);
  }
  if (assignedUser) {
    conditions.push('assigned_user = ?');
    bindings.push(assignedUser);
  }
  if (email) {
    conditions.push('assigned_user IN (SELECT id FROM users WHERE email LIKE ?)');
    bindings.push(`%${email}%`);
  }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY due_date DESC';
  const tasks = await c.env.DB.prepare(query).bind(...bindings).all();
  return c.json(tasks);
});

app.put('/tasks/:id', async (c) => {
  const { title, description, estimatedHours, dueDate, status, assignedUsers, cost } = await c.req.json();
  await c.env.DB.prepare(
    'UPDATE tasks SET title=?, description=?, estimated_hours=?, due_date=?, status=?, cost=? WHERE id=?'
  ).bind(title, description, estimatedHours, dueDate, status, cost, c.req.param('id')).run();
  return c.json({ success: true });
});

app.delete('/tasks/:id', async (c) => {
  const userId = c.get('userId');
  const user = await c.env.DB.prepare('SELECT role FROM users WHERE id = ?').bind(userId).first();
  if (user.role !== 'admin') return c.json({ error: 'Forbidden' }, 403);
  await c.env.DB.prepare('DELETE FROM tasks WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ success: true });
});

app.get('/analytics', async (c) => {
  const totalTasks = await c.env.DB.prepare('SELECT COUNT(*) as count FROM tasks').first();
  const completedTasks = await c.env.DB.prepare('SELECT COUNT(*) as count FROM tasks WHERE status = "completed"').first();
  return c.json({ totalTasks, completedTasks });
});

export default app;
