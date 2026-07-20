// =============================================
// 个人工作台后端服务
// 使用 Express + better-sqlite3 构建
// =============================================

const express = require('express');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');

// =============================================
// 配置
// =============================================

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; // 从环境变量读取，无默认值

// 数据目录
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'workbench.db');

// 确保目录存在
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// =============================================
// 初始化数据库
// =============================================

const db = new Database(DB_PATH);

// 开启 WAL 模式提升并发性能
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// 创建用户表
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
  )
`);

// 创建记录表
db.exec(`
  CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    category TEXT,
    submodule TEXT,
    title TEXT,
    date TEXT,
    status TEXT,
    priority TEXT,
    people TEXT,
    tags TEXT,
    content TEXT,
    next_step TEXT,
    course_theme TEXT,
    course_reflection TEXT,
    course_class TEXT,
    activity_audience TEXT,
    group_effect TEXT,
    group_reflection TEXT,
    schedule_day TEXT,
    schedule_period TEXT,
    resource_links TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// 创建附件表
db.exec(`
  CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mimetype TEXT,
    size INTEGER,
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
  )
`);

// 启动时检查并创建默认管理员账号
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const hash = bcrypt.hashSync('123456', 10);
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('admin', hash);
  console.log('[初始化] 已创建默认管理员账号 admin / 123456');
}

// =============================================
// 初始化 Express 应用
// =============================================

const app = express();

// 中间件
app.use(cors());
app.use(express.json({ limit: '50mb' })); // 允许较大的 JSON 请求体（用于导入导出）

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// =============================================
// JWT 验证中间件
// =============================================

// 登录接口不需要 JWT 验证
function authMiddleware(req, res, next) {
  // 获取请求头中的 Authorization 字段
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }

  const token = authHeader.slice(7);
  try {
    // 验证 JWT 令牌
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // 将用户信息挂载到请求对象上
    next();
  } catch (err) {
    return res.status(401).json({ error: '令牌无效或已过期' });
  }
}

// =============================================
// 登录接口
// =============================================

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '请提供用户名和密码' });
  }

  // 查询用户
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  // 验证密码
  const isValid = bcrypt.compareSync(password, user.password_hash);
  if (!isValid) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  // 生成 JWT 令牌，有效期 7 天
  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, username: user.username });
});

// =============================================
// 修改密码接口
// =============================================

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: '请提供旧密码和新密码' });
  }

  // 查询当前用户
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: '用户不存在' });
  }

  // 验证旧密码
  const isValid = bcrypt.compareSync(oldPassword, user.password_hash);
  if (!isValid) {
    return res.status(401).json({ error: '旧密码不正确' });
  }

  // 哈希新密码并更新
  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);

  res.json({ message: '密码修改成功' });
});

// =============================================
// 记录 CRUD 接口
// =============================================

// 获取当前用户所有记录，支持筛选
app.get('/api/records', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const { category, submodule, status, priority, dateFrom, dateTo, keyword } = req.query;

  // 构建查询条件
  let conditions = ['user_id = ?'];
  let params = [userId];

  // 按分类筛选
  if (category) {
    conditions.push('category = ?');
    params.push(category);
  }

  // 按子模块筛选
  if (submodule) {
    conditions.push('submodule = ?');
    params.push(submodule);
  }

  // 按状态筛选
  if (status) {
    conditions.push('status = ?');
    params.push(status);
  }

  // 按优先级筛选
  if (priority) {
    conditions.push('priority = ?');
    params.push(priority);
  }

  // 按日期范围筛选
  if (dateFrom) {
    conditions.push('date >= ?');
    params.push(dateFrom);
  }
  if (dateTo) {
    conditions.push('date <= ?');
    params.push(dateTo);
  }

  // 按关键词搜索（搜索标题和内容）
  if (keyword) {
    conditions.push('(title LIKE ? OR content LIKE ?)');
    const keywordPattern = `%${keyword}%`;
    params.push(keywordPattern, keywordPattern);
  }

  const whereClause = conditions.join(' AND ');
  const sql = `SELECT * FROM records WHERE ${whereClause} ORDER BY created_at DESC`;
  const records = db.prepare(sql).all(...params);

  // 获取每条记录的附件信息
  const recordIds = records.map(r => r.id);
  let attachments = [];
  if (recordIds.length > 0) {
    const placeholders = recordIds.map(() => '?').join(',');
    attachments = db.prepare(
      `SELECT * FROM attachments WHERE record_id IN (${placeholders})`
    ).all(...recordIds);
  }

  // 将附件按记录 ID 分组
  const attachmentMap = {};
  for (const att of attachments) {
    if (!attachmentMap[att.record_id]) {
      attachmentMap[att.record_id] = [];
    }
    attachmentMap[att.record_id].push(att);
  }

  // 组装返回数据
  const result = records.map(record => ({
    ...record,
    attachments: attachmentMap[record.id] || []
  }));

  res.json(result);
});

// 新增记录
app.post('/api/records', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const {
    id, category, submodule, title, date, status, priority,
    people, tags, content, next_step,
    course_theme, course_reflection, course_class,
    activity_audience, group_effect, group_reflection,
    schedule_day, schedule_period, resource_links
  } = req.body;

  // 使用客户端传入的 id，或自动生成
  const recordId = id || require('crypto').randomUUID();

  const sql = `
    INSERT INTO records (
      id, user_id, category, submodule, title, date, status, priority,
      people, tags, content, next_step,
      course_theme, course_reflection, course_class,
      activity_audience, group_effect, group_reflection,
      schedule_day, schedule_period, resource_links
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  try {
    db.prepare(sql).run(
      recordId, userId, category || null, submodule || null, title || null,
      date || null, status || null, priority || null,
      people || null, tags || null, content || null, next_step || null,
      course_theme || null, course_reflection || null, course_class || null,
      activity_audience || null, group_effect || null, group_reflection || null,
      schedule_day || null, schedule_period || null, resource_links || null
    );
    res.status(201).json({ id: recordId, message: '记录创建成功' });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: '记录 ID 已存在' });
    }
    throw err;
  }
});

// 更新记录
app.put('/api/records/:id', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const recordId = req.params.id;

  // 检查记录是否存在且属于当前用户
  const existing = db.prepare('SELECT * FROM records WHERE id = ? AND user_id = ?').get(recordId, userId);
  if (!existing) {
    return res.status(404).json({ error: '记录不存在' });
  }

  // 构建更新语句
  const fields = [
    'category', 'submodule', 'title', 'date', 'status', 'priority',
    'people', 'tags', 'content', 'next_step',
    'course_theme', 'course_reflection', 'course_class',
    'activity_audience', 'group_effect', 'group_reflection',
    'schedule_day', 'schedule_period', 'resource_links'
  ];

  const setClauses = [];
  const values = [];

  for (const field of fields) {
    if (req.body[field] !== undefined) {
      setClauses.push(`${field} = ?`);
      values.push(req.body[field]);
    }
  }

  // 始终更新 updated_at 时间戳
  setClauses.push("updated_at = datetime('now', 'localtime')");

  if (setClauses.length === 1) {
    // 没有任何字段需要更新（只有 updated_at）
    return res.json({ message: '没有需要更新的字段' });
  }

  values.push(recordId, userId);
  const sql = `UPDATE records SET ${setClauses.join(', ')} WHERE id = ? AND user_id = ?`;

  db.prepare(sql).run(...values);
  res.json({ message: '记录更新成功' });
});

// 删除记录
app.delete('/api/records/:id', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const recordId = req.params.id;

  // 检查记录是否存在且属于当前用户
  const existing = db.prepare('SELECT * FROM records WHERE id = ? AND user_id = ?').get(recordId, userId);
  if (!existing) {
    return res.status(404).json({ error: '记录不存在' });
  }

  // 删除关联的附件文件
  const attachments = db.prepare('SELECT * FROM attachments WHERE record_id = ?').all(recordId);
  for (const att of attachments) {
    const filePath = path.join(UPLOADS_DIR, att.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  // 删除记录（附件通过外键级联删除）
  db.prepare('DELETE FROM records WHERE id = ? AND user_id = ?').run(recordId, userId);

  res.json({ message: '记录删除成功' });
});

// 批量删除记录
app.post('/api/records/batch-delete', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const { ids } = req.body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: '请提供要删除的记录 ID 数组' });
  }

  // 删除前先获取关联附件并删除文件
  const placeholders = ids.map(() => '?').join(',');
  const attachments = db.prepare(
    `SELECT * FROM attachments WHERE record_id IN (${placeholders})`
  ).all(...ids);

  for (const att of attachments) {
    const filePath = path.join(UPLOADS_DIR, att.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  // 批量删除记录（仅属于当前用户的）
  const idParams = [...ids, userId];
  const result = db.prepare(
    `DELETE FROM records WHERE id IN (${placeholders}) AND user_id = ?`
  ).run(...idParams);

  res.json({ message: `成功删除 ${result.changes} 条记录` });
});

// =============================================
// 附件上传接口
// =============================================

// 配置 multer 存储
const storage = multer.diskStorage({
  // 设置上传文件保存目录
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  // 设置文件名：使用时间戳 + 随机字符串防止重名
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}${ext}`;
    cb(null, uniqueName);
  }
});

// 文件大小限制：50MB
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// 上传附件
app.post('/api/records/:id/attachments', authMiddleware, upload.array('files', 10), (req, res) => {
  const userId = req.user.id;
  const recordId = req.params.id;

  // 检查记录是否存在且属于当前用户
  const record = db.prepare('SELECT * FROM records WHERE id = ? AND user_id = ?').get(recordId, userId);
  if (!record) {
    // 如果上传了文件但记录不存在，需要清理已上传的文件
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      }
    }
    return res.status(404).json({ error: '记录不存在' });
  }

  // 将附件信息存入数据库
  const insertStmt = db.prepare(`
    INSERT INTO attachments (record_id, filename, original_name, mimetype, size)
    VALUES (?, ?, ?, ?, ?)
  `);

  const savedAttachments = [];
  const transaction = db.transaction(() => {
    for (const file of req.files) {
      const result = insertStmt.run(
        recordId,
        file.filename,
        file.originalname,
        file.mimetype,
        file.size
      );
      savedAttachments.push({
        id: result.lastInsertRowid,
        record_id: recordId,
        filename: file.filename,
        original_name: file.originalname,
        mimetype: file.mimetype,
        size: file.size
      });
    }
  });

  transaction();
  res.status(201).json({ attachments: savedAttachments });
});

// 下载附件
app.get('/api/records/:id/attachments/:attachmentId', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const recordId = req.params.id;
  const attachmentId = req.params.attachmentId;

  // 检查记录是否属于当前用户
  const record = db.prepare('SELECT * FROM records WHERE id = ? AND user_id = ?').get(recordId, userId);
  if (!record) {
    return res.status(404).json({ error: '记录不存在' });
  }

  // 查询附件信息
  const attachment = db.prepare('SELECT * FROM attachments WHERE id = ? AND record_id = ?')
    .get(attachmentId, recordId);

  if (!attachment) {
    return res.status(404).json({ error: '附件不存在' });
  }

  const filePath = path.join(UPLOADS_DIR, attachment.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: '附件文件已丢失' });
  }

  // 返回附件文件
  res.download(filePath, attachment.original_name);
});

// 删除附件
app.delete('/api/records/:id/attachments/:attachmentId', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const recordId = req.params.id;
  const attachmentId = req.params.attachmentId;

  // 检查记录是否属于当前用户
  const record = db.prepare('SELECT * FROM records WHERE id = ? AND user_id = ?').get(recordId, userId);
  if (!record) {
    return res.status(404).json({ error: '记录不存在' });
  }

  // 查询附件信息
  const attachment = db.prepare('SELECT * FROM attachments WHERE id = ? AND record_id = ?')
    .get(attachmentId, recordId);

  if (!attachment) {
    return res.status(404).json({ error: '附件不存在' });
  }

  // 删除物理文件
  const filePath = path.join(UPLOADS_DIR, attachment.filename);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  // 从数据库中删除附件记录
  db.prepare('DELETE FROM attachments WHERE id = ?').run(attachmentId);

  res.json({ message: '附件删除成功' });
});

// =============================================
// 数据导入导出接口
// =============================================

// 导出当前用户所有记录为 JSON
app.get('/api/export', authMiddleware, (req, res) => {
  const userId = req.user.id;

  // 查询所有记录
  const records = db.prepare('SELECT * FROM records WHERE user_id = ? ORDER BY created_at DESC').all(userId);

  // 查询所有附件信息
  const recordIds = records.map(r => r.id);
  let attachments = [];
  if (recordIds.length > 0) {
    const placeholders = recordIds.map(() => '?').join(',');
    attachments = db.prepare(
      `SELECT * FROM attachments WHERE record_id IN (${placeholders})`
    ).all(...recordIds);
  }

  // 组装导出数据
  const exportData = {
    exportTime: new Date().toISOString(),
    records: records.map(record => ({
      ...record,
      attachments: attachments.filter(a => a.record_id === record.id)
    }))
  };

  res.json(exportData);
});

// 导入 JSON 数据
app.post('/api/import', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const merge = req.query.merge === 'true'; // 是否为合并模式

  // 验证导入数据格式
  const importData = req.body;
  if (!importData.records || !Array.isArray(importData.records)) {
    return res.status(400).json({ error: '导入数据格式错误，需要包含 records 数组' });
  }

  const insertRecord = db.prepare(`
    INSERT OR IGNORE INTO records (
      id, user_id, category, submodule, title, date, status, priority,
      people, tags, content, next_step,
      course_theme, course_reflection, course_class,
      activity_audience, group_effect, group_reflection,
      schedule_day, schedule_period, resource_links
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertAttachment = db.prepare(`
    INSERT OR IGNORE INTO attachments (record_id, filename, original_name, mimetype, size)
    VALUES (?, ?, ?, ?, ?)
  `);

  const updateRecord = db.prepare(`
    UPDATE records SET
      category = ?, submodule = ?, title = ?, date = ?, status = ?, priority = ?,
      people = ?, tags = ?, content = ?, next_step = ?,
      course_theme = ?, course_reflection = ?, course_class = ?,
      activity_audience = ?, group_effect = ?, group_reflection = ?,
      schedule_day = ?, schedule_period = ?, resource_links = ?,
      updated_at = datetime('now', 'localtime')
    WHERE id = ? AND user_id = ?
  `);

  let imported = 0;
  let updated = 0;

  const transaction = db.transaction(() => {
    for (const record of importData.records) {
      const recordId = record.id;
      if (!recordId) continue;

      // 检查记录是否已存在
      const existing = db.prepare('SELECT id FROM records WHERE id = ? AND user_id = ?')
        .get(recordId, userId);

      if (existing) {
        if (merge) {
          // 合并模式：更新已存在的记录
          updateRecord.run(
            record.category || null, record.submodule || null, record.title || null,
            record.date || null, record.status || null, record.priority || null,
            record.people || null, record.tags || null, record.content || null,
            record.next_step || null,
            record.course_theme || null, record.course_reflection || null,
            record.course_class || null,
            record.activity_audience || null, record.group_effect || null,
            record.group_reflection || null,
            record.schedule_day || null, record.schedule_period || null,
            record.resource_links || null,
            recordId, userId
          );
          updated++;
        }
        // 非合并模式：跳过已存在的记录（INSERT OR IGNORE 会自动跳过）
      } else {
        // 插入新记录
        insertRecord.run(
          recordId, userId,
          record.category || null, record.submodule || null, record.title || null,
          record.date || null, record.status || null, record.priority || null,
          record.people || null, record.tags || null, record.content || null,
          record.next_step || null,
          record.course_theme || null, record.course_reflection || null,
          record.course_class || null,
          record.activity_audience || null, record.group_effect || null,
          record.group_reflection || null,
          record.schedule_day || null, record.schedule_period || null,
          record.resource_links || null
        );
        imported++;
      }

      // 导入附件信息（仅记录元数据，不导入实际文件）
      if (record.attachments && Array.isArray(record.attachments)) {
        for (const att of record.attachments) {
          insertAttachment.run(
            att.record_id || recordId,
            att.filename,
            att.original_name,
            att.mimetype || null,
            att.size || null
          );
        }
      }
    }
  });

  try {
    transaction();
    res.json({
      message: '数据导入完成',
      imported,   // 新增数量
      updated,    // 更新数量（仅合并模式）
      total: importData.records.length
    });
  } catch (err) {
    res.status(500).json({ error: '导入过程中发生错误', detail: err.message });
  }
});

// =============================================
// 启动服务器
// =============================================

app.listen(PORT, () => {
  console.log(`[启动] 工作台后端服务运行在 http://localhost:${PORT}`);
  console.log(`[启动] 数据库文件：${DB_PATH}`);
  console.log(`[启动] 上传目录：${UPLOADS_DIR}`);
});