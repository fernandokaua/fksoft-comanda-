// VERSÃO FINAL E DEFINITIVA - TODAS AS ROTAS 100% COMPLETAS

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'SEGREDO_SUPER_SECRETO_PARA_ASSINAR_OS_TOKENS';

// --- Conexão Inteligente com o Banco de Dados ---
const isProduction = !!process.env.DATABASE_URL;
const connectionConfig = isProduction
  ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
  : { user: 'postgres', host: 'localhost', database: 'fksoft_db', password: '12345', port: 5432 };
const pool = new Pool(connectionConfig);

// Middlewares
app.use(cors());
app.use(express.json());

// --- Função de Setup do Banco de Dados (Versão Robusta) ---
async function setupDatabase() {
    const client = await pool.connect();
    try {
        console.log("Conectado ao PostgreSQL! Verificando estrutura do banco de dados...");
        const addColumnIfNotExists = async (tableName, columnName, columnType) => {
            const res = await client.query(`SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`, [tableName, columnName]);
            if (res.rowCount === 0) {
                await client.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`);
                console.log(`>> Coluna '${columnName}' adicionada à tabela '${tableName}'.`);
            }
        };
        await client.query(`CREATE TABLE IF NOT EXISTS lojas (id SERIAL PRIMARY KEY, nome TEXT NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, role TEXT NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS estoque (id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, preco REAL NOT NULL, quantidade INTEGER NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS vendas (id SERIAL PRIMARY KEY, cliente_nome TEXT, produto_nome TEXT NOT NULL, produto_preco REAL NOT NULL, metodo_pagamento TEXT NOT NULL, desconto REAL DEFAULT 0, data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS compras (id SERIAL PRIMARY KEY, produto TEXT NOT NULL, valor REAL NOT NULL, metodo_pagamento TEXT NOT NULL, data_compra DATE NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);
        
        console.log(">> Estrutura de tabelas e colunas verificada.");

        const lojasRes = await client.query('SELECT * FROM lojas LIMIT 1');
        if (lojasRes.rowCount === 0) {
            await client.query("INSERT INTO lojas (nome) VALUES ('Loja Padrão')");
            console.log('>> Loja Padrão criada.');
        }

        const adminRes = await client.query('SELECT * FROM usuarios WHERE usuario = $1', ['admin']);
        if (adminRes.rowCount === 0) {
            const adminPass = 'admin123';
            const hash = await bcrypt.hash(adminPass, SALT_ROUNDS);
            await client.query('INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)', ['admin', hash, 'admin', 1]);
            console.log('>> Usuário "admin" criado e associado à Loja Padrão.');
        } else {
            await client.query("UPDATE usuarios SET loja_id = 1 WHERE usuario = 'admin' AND loja_id IS NULL");
        }
        
        const superAdminRes = await client.query('SELECT * FROM usuarios WHERE usuario = $1', ['superadmin']);
        if (superAdminRes.rowCount === 0) {
            const superAdminPass = 'senhaforte123';
            const hash = await bcrypt.hash(superAdminPass, SALT_ROUNDS);
            await client.query('INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, NULL)', ['superadmin', hash, 'superadmin']);
            console.log('>> Usuário "superadmin" criado.');
        }
        
        console.log('Tabelas do banco de dados prontas.');
    } catch (err) {
        console.error('Erro CRÍTICO durante o setup do banco de dados:', err);
        process.exit(1);
    } finally {
        client.release();
    }
}

// --- Middlewares de Autenticação ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function isSuperAdmin(req, res, next) {
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Acesso negado.' });
    }
    next();
}

// --- ROTAS DA API ---

// ROTA DE LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { usuario, senha } = req.body;
        const result = await pool.query('SELECT id, usuario, senha, role, loja_id FROM usuarios WHERE usuario = $1', [usuario]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
        const match = await bcrypt.compare(senha, user.senha);
        if (match) {
            const payload = { userId: user.id, lojaId: user.loja_id, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
            res.json({ message: "Login bem-sucedido", token, role: user.role });
        } else { res.status(401).json({ error: "Senha incorreta" }); }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ROTAS DO SUPER ADMIN
app.get('/api/superadmin/lojas', authenticateToken, isSuperAdmin, async (req, res) => {
    const result = await pool.query('SELECT * FROM lojas ORDER BY nome ASC');
    res.json(result.rows);
});

app.post('/api/superadmin/lojas', authenticateToken, isSuperAdmin, async (req, res) => {
    const { nomeLoja, usuarioAdmin, senhaAdmin } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const lojaQuery = 'INSERT INTO lojas (nome) VALUES ($1) RETURNING id';
        const lojaResult = await client.query(lojaQuery, [nomeLoja]);
        const novaLojaId = lojaResult.rows[0].id;
        const hash = await bcrypt.hash(senhaAdmin, SALT_ROUNDS);
        const userQuery = 'INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)';
        await client.query(userQuery, [usuarioAdmin, hash, 'admin', novaLojaId]);
        await client.query('COMMIT');
        res.status(201).json({ message: `Loja "${nomeLoja}" e seu admin "${usuarioAdmin}" criados com sucesso!` });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Erro ao criar nova loja: ' + err.message });
    } finally {
        client.release();
    }
});

app.get('/api/superadmin/usuarios', authenticateToken, isSuperAdmin, async (req, res) => {
    const { lojaId } = req.query;
    const result = await pool.query('SELECT id, usuario, role FROM usuarios WHERE loja_id = $1', [lojaId]);
    res.json(result.rows);
});

app.put('/api/superadmin/usuarios/:userId/role', authenticateToken, isSuperAdmin, async (req, res) => {
    const { userId } = req.params;
    const { role } = req.body;
    await pool.query('UPDATE usuarios SET role = $1 WHERE id = $2', [role, userId]);
    res.json({ message: 'Cargo do usuário atualizado com sucesso!' });
});

// ROTAS PADRÃO DO SISTEMA (PARA ADMINS E CAIXAS)

app.get('/api/dashboard', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const queryVendasHoje = "SELECT SUM(produto_preco - desconto) as total FROM vendas WHERE loja_id = $1 AND DATE(data_venda) = CURRENT_DATE";
    const vendasResult = await pool.query(queryVendasHoje, [lojaId]);
    const totalVendasHoje = parseFloat(vendasResult.rows[0].total) || 0;
    const queryEstoqueBaixo = "SELECT COUNT(*) as count FROM estoque WHERE loja_id = $1 AND quantidade < 10";
    const estoqueResult = await pool.query(queryEstoqueBaixo, [lojaId]);
    const estoqueBaixoCount = parseInt(estoqueResult.rows[0].count) || 0;
    res.json({ totalVendasHoje, estoqueBaixoCount });
});

app.get('/api/estoque', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM estoque WHERE loja_id = $1 ORDER BY nome', [lojaId]);
    res.json(result.rows);
});

app.get('/api/estoque/:codigo', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const { codigo } = req.params;
    const result = await pool.query('SELECT nome, preco, quantidade FROM estoque WHERE codigo = $1 AND loja_id = $2', [codigo, lojaId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
    res.json(result.rows[0]);
});

app.post('/api/estoque', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const { codigo, nome, preco, quantidade } = req.body;
    const query = `INSERT INTO estoque (codigo, nome, preco, quantidade, loja_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (codigo) DO UPDATE SET quantidade = estoque.quantidade + $4, preco = $3`;
    await pool.query(query, [codigo, nome, parseFloat(preco), parseInt(quantidade), lojaId]);
    res.status(201).json({ message: "Produto adicionado/atualizado!" });
});

app.put('/api/estoque/:codigo/adicionar', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const { quantidade } = req.body;
    const query = 'UPDATE estoque SET quantidade = quantidade + $1 WHERE codigo = $2 AND loja_id = $3';
    await pool.query(query, [parseInt(quantidade), req.params.codigo, lojaId]);
    res.json({ message: 'Estoque atualizado com sucesso!' });
});

app.delete('/api/estoque/:codigo', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const query = 'DELETE FROM estoque WHERE codigo = $1 AND loja_id = $2';
    await pool.query(query, [req.params.codigo, lojaId]);
    res.json({ message: 'Produto excluído com sucesso!' });
});

app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { lojaId } = req.user;
    const result = await pool.query('SELECT id, usuario, role FROM usuarios WHERE loja_id = $1 ORDER BY usuario', [lojaId]);
    res.json(result.rows);
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { usuario, senha, role } = req.body;
    const { lojaId } = req.user;
    const hash = await bcrypt.hash(senha, SALT_ROUNDS);
    await pool.query('INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)', [usuario, hash, role, lojaId]);
    res.status(201).json({ message: 'Usuário criado com sucesso!'});
});

app.delete('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { id } = req.params;
    const { userId } = req.user;
    if (parseInt(id, 10) === userId) return res.status(400).json({ error: 'Você não pode excluir a si mesmo.' });
    await pool.query('DELETE FROM usuarios WHERE id = $1', [id]);
    res.json({ message: 'Usuário excluído com sucesso!' });
});

app.get('/api/relatorios/vendas', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM vendas WHERE loja_id = $1 ORDER BY data_venda DESC', [lojaId]);
    res.json(result.rows);
});

app.get('/api/relatorios/compras', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM compras WHERE loja_id = $1 ORDER BY data_compra DESC', [lojaId]);
    res.json(result.rows);
});

app.post('/api/relatorios/compras', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const { dataCompra, metodoPagamento, produto, valor } = req.body;
    await pool.query('INSERT INTO compras (data_compra, metodo_pagamento, produto, valor, loja_id) VALUES ($1, $2, $3, $4, $5)', [dataCompra, metodoPagamento, produto, parseFloat(valor), lojaId]);
    res.status(201).json({ message: "Compra registrada!" });
});

app.post('/api/vendas', authenticateToken, async (req, res) => {
    const { itens, metodoPagamento, desconto, clienteNome } = req.body;
    const { lojaId } = req.user;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const insertVendaQuery = "INSERT INTO vendas (produto_nome, produto_preco, metodo_pagamento, desconto, loja_id, cliente_nome) VALUES ($1, $2, $3, $4, $5, $6)";
        const updateEstoqueQuery = "UPDATE estoque SET quantidade = quantidade - 1 WHERE codigo = $1 AND loja_id = $2 AND quantidade > 0";
        for (const item of itens) {
            const descontoPorItem = (desconto / itens.length) || 0;
            await client.query(insertVendaQuery, [item.nome, item.preco, metodoPagamento, descontoPorItem, lojaId, clienteNome]);
            const estoqueResult = await client.query(updateEstoqueQuery, [item.codigo, lojaId]);
            if (estoqueResult.rowCount === 0) throw new Error(`Estoque insuficiente para ${item.nome}`);
        }
        await client.query('COMMIT');
        res.status(201).json({message: "Vendas registradas!"});
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({error: err.message});
    } finally {
        client.release();
    }
});

// --- SERVIR ARQUIVOS DO FRONTEND ---
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// --- INICIALIZAÇÃO CORRETA DO SERVIDOR ---
setupDatabase().then(() => {
    app.listen(port, () => {
        console.log(`--- Servidor pronto para conexões na porta ${port} ---`);
    });
}).catch(err => {
    console.error("Falha ao iniciar o servidor:", err);
});