import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-workers';
import { createHash, randomBytes } from 'crypto';

type Bindings = {
  KVSESS: KVNamespace;
  PUULDB: D1Database;
};

const app = new Hono();

const hashPassword = (password, salt) => {
  return createHash('sha256').update(password + salt).digest('hex');
};


app.post('/register', async (c) => {
  const { name, password, email, role } = await c.req.json();
  const salt = randomBytes(16).toString('hex');
  const hashedPassword = hashPassword(password, salt);
  const password_hash = `${hashedPassword}:${salt}`;

  await c.env.PUULDB.prepare(
    'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)'
  ).bind(name, email, password_hash, role || 'member').run();

  return c.json({ success: true });
});


app.post('/login', async (c) => {
  const { email, password } = await c.req.json();
  let user;
  try {
    user = await c.env.PUULDB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).first();
  } catch (error) {
    return c.json({ error: 'Internal Server Error' }, 500);
  }

  if (!user) {
    return c.json({ error: 'User not found' }, 401);
  }

  let [hashedPassword, salt] = user.password_hash.split(':');
  if (!user || hashPassword(password, salt) !== hashedPassword) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const sessionKey = randomBytes(32).toString('hex');
  await c.env.KVSESS.put(`session:${sessionKey}`, user.id, { expirationTtl: 86400 });

  return c.json({ sessionKey });
});


app.use(async (c, next) => {
  const sessionKey = c.req.header('Authorization');
  if (!sessionKey) return c.json({ error: 'Unauthorized' }, 401);
  const userId = await c.env.KVSESS.get(`session:${sessionKey}`);
  if (!userId) return c.json({ error: 'Invalid session' }, 401);
  c.set('userId', userId);
  await next();
});

app.get('/me', async (c) => {
  const userId = c.get('userId');
  const user = await c.env.PUULDB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
  return c.json(user);
} );



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
  const users = await c.env.PUULDB.prepare(query).bind(...bindings).all();
  return c.json(users);
});



// Task Endpoints
app.post('/tasks', async (c) => {
  const { title, description, estimatedHours, dueDate, status, cost, assignedUsers } = await c.req.json();
  
  const taskResult = await c.env.PUULDB.prepare(
    'INSERT INTO tasks (title, description, estimated_hours, due_date, status, cost) VALUES (?, ?, ?, ?, ?, ?) RETURNING id'
  ).bind(title, description, estimatedHours, dueDate, status, cost).first();
  
  if (!taskResult) return c.json({ error: 'Failed to create task' }, 500);
  const taskId = taskResult.id;

  if (assignedUsers && assignedUsers.length > 0) {
    const users = await c.env.PUULDB.prepare(
      `SELECT id FROM users WHERE email IN (${assignedUsers.map(() => '?').join(',')})`
    ).bind(...assignedUsers).all();
    
    const userIds = users.results.map(user => user.id);
    for (const userId of userIds) {
      await c.env.PUULDB.prepare('INSERT INTO task_assignments (task_id, user_id) VALUES (?, ?)')
        .bind(taskId, userId).run();
    }
  }

  return c.json({ success: true, taskId });
});

app.get('/tasks', async (c) => {
  const { dueDate, name, assignedUser, email } = c.req.query();
  let query = `SELECT tasks.*, 
                      json_group_array(json_object('name', users.name, 'email', users.email)) AS assignedUsersRaw 
               FROM tasks 
               LEFT JOIN task_assignments ON tasks.id = task_assignments.task_id 
               LEFT JOIN users ON task_assignments.user_id = users.id`;
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
    conditions.push('task_assignments.user_id = ?');
    bindings.push(assignedUser);
  }
  if (email) {
    conditions.push('users.email LIKE ?');
    bindings.push(`%${email}%`);
  }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  query += ' GROUP BY tasks.id ORDER BY due_date DESC';
  const tasks = await c.env.PUULDB.prepare(query).bind(...bindings).all();

  tasks.results = tasks.results.map(task => ({
    ...task,
    assignedUsers: JSON.parse(task.assignedUsersRaw || '[]')
  }));
  
  return c.json(tasks);
});

app.put('/tasks/:id', async (c) => {
  const { title, description, estimatedHours, dueDate, status, cost, assignedUsers } = await c.req.json();
  const taskId = c.req.param('id');

  await c.env.PUULDB.prepare(
    'UPDATE tasks SET title=?, description=?, estimated_hours=?, due_date=?, status=?, cost=? WHERE id=?'
  ).bind(title, description, estimatedHours, dueDate, status, cost, taskId).run();

  if (assignedUsers) {
    await c.env.PUULDB.prepare('DELETE FROM task_assignments WHERE task_id = ?').bind(taskId).run();
    
    const users = await c.env.PUULDB.prepare(
      `SELECT id FROM users WHERE email IN (${assignedUsers.map(() => '?').join(',')})`
    ).bind(...assignedUsers).all();
    
    const userIds = users.results.map(user => user.id);
    for (const userId of userIds) {
      await c.env.PUULDB.prepare('INSERT INTO task_assignments (task_id, user_id) VALUES (?, ?)')
        .bind(taskId, userId).run();
    }
  }

  return c.json({ success: true });
});

app.delete('/tasks/:id', async (c) => {
  const userId = c.get('userId');
  const user = await c.env.PUULDB.prepare('SELECT role FROM users WHERE id = ?').bind(userId).first();
  if (user.role !== 'admin') return c.json({ error: 'Forbidden' }, 403);
  await c.env.PUULDB.prepare('DELETE FROM tasks WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ success: true });
});

app.get('/analytics', async (c) => {
  const totalTasks = await c.env.PUULDB.prepare('SELECT COUNT(*) as count FROM tasks').first();
  const completedTasks = await c.env.PUULDB.prepare('SELECT COUNT(*) as count FROM tasks WHERE status = "completed"').first();
  return c.json({ totalTasks, completedTasks });
});

export default app;
