// VERSÃO DEFINITIVA E COMPLETA - TODAS AS ROTAS INCLUÍDAS E CORRIGIDAS

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
        await client.query(`CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, role TEXT NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS estoque (id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, preco REAL NOT NULL, quantidade INTEGER NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS vendas (id SERIAL PRIMARY KEY, produto_nome TEXT NOT NULL, produto_preco REAL NOT NULL, metodo_pagamento TEXT NOT NULL, desconto REAL DEFAULT 0, data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP)`);
        await client.query(`CREATE TABLE IF NOT EXISTS compras (id SERIAL PRIMARY KEY, produto TEXT NOT NULL, valor REAL NOT NULL, metodo_pagamento TEXT NOT NULL, data_compra DATE NOT NULL)`);
        
        await addColumnIfNotExists('usuarios', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('estoque', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('vendas', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('compras', 'loja_id', 'INTEGER REFERENCES lojas(id)');

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
        
        console.log('Tabelas do banco de dados prontas.');
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
            res.json({ message: "Login bem-sucedido", token: token, role: user.role });
        } else { res.status(401).json({ error: "Senha incorreta" }); }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ROTA PARA DASHBOARD
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const queryVendasHoje = "SELECT SUM(produto_preco - desconto) as total FROM vendas WHERE loja_id = $1 AND DATE(data_venda) = CURRENT_DATE";
        const vendasResult = await pool.query(queryVendasHoje, [lojaId]);
        const totalVendasHoje = parseFloat(vendasResult.rows[0].total) || 0;
        const queryEstoqueBaixo = "SELECT COUNT(*) as count FROM estoque WHERE loja_id = $1 AND quantidade < 10";
        const estoqueResult = await pool.query(queryEstoqueBaixo, [lojaId]);
        const estoqueBaixoCount = parseInt(estoqueResult.rows[0].count) || 0;
        res.json({ totalVendasHoje, estoqueBaixoCount });
    } catch(err) { res.status(500).json({error: "Erro ao buscar dados do dashboard"}); }
});

// ROTAS DE ESTOQUE
app.get('/api/estoque', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM estoque WHERE loja_id = $1 ORDER BY nome', [lojaId]);
    res.json(result.rows);
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
    const result = await pool.query(query, [parseInt(quantidade), req.params.codigo, lojaId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
    res.json({ message: 'Estoque atualizado com sucesso!' });
});

app.delete('/api/estoque/:codigo', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const query = 'DELETE FROM estoque WHERE codigo = $1 AND loja_id = $2';
    const result = await pool.query(query, [req.params.codigo, lojaId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
    res.json({ message: 'Produto excluído com sucesso!' });
});

// ROTAS DE USUÁRIOS
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
    if (!usuario || !senha || !role) return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    const hash = await bcrypt.hash(senha, SALT_ROUNDS);
    const query = 'INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)';
    await pool.query(query, [usuario, hash, role, lojaId]);
    res.status(201).json({ message: 'Usuário criado com sucesso!'});
});

// ROTAS DE RELATÓRIOS E VENDAS
app.get('/api/relatorios/vendas', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM vendas WHERE loja_id = $1 ORDER BY data_venda DESC', [lojaId]);
    res.json(result.rows);
});

app.post('/api/vendas', authenticateToken, async (req, res) => {
    const { itens, metodoPagamento, desconto } = req.body;
    const { lojaId } = req.user;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const insertVendaQuery = "INSERT INTO vendas (produto_nome, produto_preco, metodo_pagamento, desconto, loja_id) VALUES ($1, $2, $3, $4, $5)";
        const updateEstoqueQuery = "UPDATE estoque SET quantidade = quantidade - 1 WHERE codigo = $1 AND loja_id = $2 AND quantidade > 0";
        const descontoPorItem = (desconto / itens.length) || 0;
        for (const item of itens) {
            await client.query(insertVendaQuery, [item.nome, item.preco, metodoPagamento, descontoPorItem, lojaId]);
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

app.get('/api/relatorios/compras', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const result = await pool.query('SELECT * FROM compras WHERE loja_id = $1 ORDER BY data_compra DESC', [lojaId]);
    res.json(result.rows);
});

app.post('/api/relatorios/compras', authenticateToken, async (req, res) => {
    const { lojaId } = req.user;
    const { dataCompra, metodoPagamento, produto, valor } = req.body;
    const query = 'INSERT INTO compras (data_compra, metodo_pagamento, produto, valor, loja_id) VALUES ($1, $2, $3, $4, $5)';
    await pool.query(query, [dataCompra, metodoPagamento, produto, parseFloat(valor), lojaId]);
    res.status(201).json({ message: "Compra registrada!" });
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