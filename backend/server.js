// VERSÃO FINAL E COMPLETA - USANDO EXPRESS + POSTGRESQL

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// --- Conexão com o Banco de Dados PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middlewares
app.use(cors());
app.use(express.json());

// --- Função para criar o Schema do Banco de Dados ---
async function setupDatabase() {
    const client = await pool.connect();
    try {
        console.log("Conectado ao PostgreSQL! Verificando tabelas...");
        await client.query(`
            CREATE TABLE IF NOT EXISTS usuarios ( id SERIAL PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, role TEXT NOT NULL );
            CREATE TABLE IF NOT EXISTS estoque ( id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, preco REAL NOT NULL, quantidade INTEGER NOT NULL );
            CREATE TABLE IF NOT EXISTS vendas ( id SERIAL PRIMARY KEY, produto_nome TEXT NOT NULL, produto_preco REAL NOT NULL, metodo_pagamento TEXT NOT NULL, desconto REAL DEFAULT 0, data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP );
            CREATE TABLE IF NOT EXISTS compras ( id SERIAL PRIMARY KEY, produto TEXT NOT NULL, valor REAL NOT NULL, metodo_pagamento TEXT NOT NULL, data_compra DATE NOT NULL );
        `);
        const res = await client.query('SELECT * FROM usuarios WHERE usuario = $1', ['admin']);
        if (res.rowCount === 0) {
            const adminPass = 'admin123';
            const hash = await bcrypt.hash(adminPass, SALT_ROUNDS);
            await client.query('INSERT INTO usuarios (usuario, senha, role) VALUES ($1, $2, $3)', ['admin', hash, 'admin']);
            console.log('Usuário "admin" criado com senha "admin123"');
        }
        console.log('Tabelas do banco de dados verificadas/criadas com sucesso.');
    } catch (err) {
        console.error('Erro durante o setup do banco de dados:', err);
    } finally {
        client.release();
    }
}

setupDatabase().then(() => {
    app.listen(port, () => {
        console.log(`\n--- SERVIDOR PRONTO E RODANDO EM http://localhost:${port} ---`);
    });
});

// --- ROTAS DA API ---

// ROTA DE LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { usuario, senha } = req.body;
        const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
        const match = await bcrypt.compare(senha, user.senha);
        if (match) res.json({ message: "Login bem-sucedido", role: user.role });
        else res.status(401).json({ error: "Senha incorreta" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ROTAS DE ESTOQUE ---
app.get('/api/estoque', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM estoque ORDER BY nome');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/estoque', async (req, res) => {
    try {
        const { codigo, nome, preco, quantidade } = req.body;
        const query = `
            INSERT INTO estoque (codigo, nome, preco, quantidade) VALUES ($1, $2, $3, $4) 
            ON CONFLICT (codigo) DO UPDATE SET quantidade = estoque.quantidade + $4, preco = $3`;
        await pool.query(query, [codigo, nome, parseFloat(preco), parseInt(quantidade)]);
        res.status(201).json({ message: "Produto adicionado/atualizado!" });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/estoque/:codigo/adicionar', async (req, res) => {
    try {
        const { quantidade } = req.body;
        const query = 'UPDATE estoque SET quantidade = quantidade + $1 WHERE codigo = $2';
        const result = await pool.query(query, [parseInt(quantidade), req.params.codigo]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
        res.json({ message: 'Estoque atualizado com sucesso!' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/estoque/:codigo', async (req, res) => {
    try {
        const query = 'DELETE FROM estoque WHERE codigo = $1';
        const result = await pool.query(query, [req.params.codigo]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
        res.json({ message: 'Produto excluído com sucesso!' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// --- ROTAS DE USUÁRIOS ---
app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, usuario, role FROM usuarios ORDER BY usuario');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/usuarios', async (req, res) => {
    const { usuario, senha, role } = req.body;
    if (!usuario || !senha || !role) return res.status(400).json({ error: 'Usuário, senha e cargo são obrigatórios.' });
    try {
        const hash = await bcrypt.hash(senha, SALT_ROUNDS);
        const query = 'INSERT INTO usuarios (usuario, senha, role) VALUES ($1, $2, $3) RETURNING id';
        const result = await pool.query(query, [usuario, hash, role]);
        res.status(201).json({ message: 'Usuário criado com sucesso!', userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Este nome de usuário já existe.' });
        res.status(500).json({ error: err.message });
    }
});

// --- ROTAS DE RELATÓRIOS E VENDAS ---
app.get('/api/relatorios/vendas', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM vendas ORDER BY data_venda DESC');
        res.json(result.rows);
    } catch(err) { res.status(500).json({error: err.message}); }
});

app.get('/api/relatorios/compras', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM compras ORDER BY data_compra DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/relatorios/compras', async (req, res) => {
    try {
        const { dataCompra, metodoPagamento, produto, valor } = req.body;
        const query = 'INSERT INTO compras (data_compra, metodo_pagamento, produto, valor) VALUES ($1, $2, $3, $4)';
        await pool.query(query, [dataCompra, metodoPagamento, produto, parseFloat(valor)]);
        res.status(201).json({ message: "Compra registrada!" });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/vendas', async (req, res) => {
    const { itens, metodoPagamento, desconto } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const insertVendaQuery = "INSERT INTO vendas (produto_nome, produto_preco, metodo_pagamento, desconto) VALUES ($1, $2, $3, $4)";
        const updateEstoqueQuery = "UPDATE estoque SET quantidade = quantidade - 1 WHERE codigo = $1 AND quantidade > 0";
        const descontoPorItem = (desconto / itens.length) || 0;
        for (const item of itens) {
            await client.query(insertVendaQuery, [item.nome, item.preco, metodoPagamento, descontoPorItem]);
            const estoqueResult = await client.query(updateEstoqueQuery, [item.codigo]);
            if (estoqueResult.rowCount === 0) throw new Error(`Estoque insuficiente para o produto ${item.nome}`);
        }
        await client.query('COMMIT');
        res.status(201).json({message: "Vendas registradas e estoque atualizado!"});
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({error: "Erro ao registrar vendas: " + err.message});
    } finally {
        client.release();
    }
});

// --- ROTA PARA DASHBOARD ---
app.get('/api/dashboard', async (req, res) => {
    try {
        const queryVendasHoje = "SELECT SUM(produto_preco - desconto) as total FROM vendas WHERE DATE(data_venda) = CURRENT_DATE";
        const vendasResult = await pool.query(queryVendasHoje);
        const totalVendasHoje = parseFloat(vendasResult.rows[0].total) || 0;
        const queryEstoqueBaixo = "SELECT COUNT(*) as count FROM estoque WHERE quantidade < 10";
        const estoqueResult = await pool.query(queryEstoqueBaixo);
        const estoqueBaixoCount = parseInt(estoqueResult.rows[0].count) || 0;
        res.json({ totalVendasHoje, estoqueBaixoCount });
    } catch(err) {
        console.error("Erro na rota dashboard:", err.message);
        res.status(500).json({error: "Erro interno do servidor"});
    }
});

// --- SERVIR ARQUIVOS DO FRONTEND ---
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});