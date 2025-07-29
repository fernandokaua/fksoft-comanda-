// VERSÃO DEFINITIVAMENTE FINAL - CORRIGE A INICIALIZAÇÃO DO BANCO DE DADOS

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json());

// --- Função para criar o Schema do Banco de Dados ---
async function setupDatabase() {
    const client = await pool.connect();
    try {
        console.log("Conectado ao PostgreSQL! Verificando tabelas...");
        
        await client.query(`CREATE TABLE IF NOT EXISTS lojas (id SERIAL PRIMARY KEY, nome TEXT NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, role TEXT NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS estoque (id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, preco REAL NOT NULL, quantidade INTEGER NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS vendas (id SERIAL PRIMARY KEY, produto_nome TEXT NOT NULL, produto_preco REAL NOT NULL, metodo_pagamento TEXT NOT NULL, desconto REAL DEFAULT 0, data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, loja_id INTEGER REFERENCES lojas(id))`);
        await client.query(`CREATE TABLE IF NOT EXISTS compras (id SERIAL PRIMARY KEY, produto TEXT NOT NULL, valor REAL NOT NULL, metodo_pagamento TEXT NOT NULL, data_compra DATE NOT NULL, loja_id INTEGER REFERENCES lojas(id))`);

        const lojasRes = await client.query('SELECT * FROM lojas LIMIT 1');
        if (lojasRes.rowCount === 0) {
            await client.query("INSERT INTO lojas (nome) VALUES ('Loja Padrão')");
            console.log('Loja Padrão criada.');
        }

        const res = await client.query('SELECT * FROM usuarios WHERE usuario = $1', ['admin']);
        if (res.rowCount === 0) {
            const adminPass = 'admin123';
            const hash = await bcrypt.hash(adminPass, SALT_ROUNDS);
            await client.query('INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)', ['admin', hash, 'admin', 1]);
            console.log('Usuário "admin" criado com senha "admin123" na Loja Padrão.');
        }
        console.log('Tabelas do banco de dados verificadas/criadas com sucesso.');
    } catch (err) {
        console.error('Erro CRÍTICO durante o setup do banco de dados:', err);
        process.exit(1);
    } finally {
        client.release();
    }
}

// --- Middleware de Autenticação ---
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

// --- ROTAS DA API ---
// (Todas as rotas que já tínhamos continuam aqui, inalteradas)
app.post('/api/login', async (req, res) => {
    try {
        const { usuario, senha } = req.body;
        const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
        const match = await bcrypt.compare(senha, user.senha);
        if (match) {
            const payload = { userId: user.id, lojaId: user.loja_id, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
            res.json({ message: "Login bem-sucedido", token: token, role: user.role });
        } else {
            res.status(401).json({ error: "Senha incorreta" });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/estoque', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const result = await pool.query('SELECT * FROM estoque WHERE loja_id = $1 ORDER BY nome', [lojaId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/estoque', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const { codigo, nome, preco, quantidade } = req.body;
        const query = `INSERT INTO estoque (codigo, nome, preco, quantidade, loja_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (codigo) DO UPDATE SET quantidade = estoque.quantidade + $4, preco = $3`;
        await pool.query(query, [codigo, nome, parseFloat(preco), parseInt(quantidade), lojaId]);
        res.status(201).json({ message: "Produto adicionado/atualizado!" });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/estoque/:codigo/adicionar', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const { quantidade } = req.body;
        const query = 'UPDATE estoque SET quantidade = quantidade + $1 WHERE codigo = $2 AND loja_id = $3';
        const result = await pool.query(query, [parseInt(quantidade), req.params.codigo, lojaId]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
        res.json({ message: 'Estoque atualizado com sucesso!' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/estoque/:codigo', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const query = 'DELETE FROM estoque WHERE codigo = $1 AND loja_id = $2';
        const result = await pool.query(query, [req.params.codigo, lojaId]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
        res.json({ message: 'Produto excluído com sucesso!' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// ... (outras rotas como /api/usuarios, /api/vendas, etc. continuam aqui)


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