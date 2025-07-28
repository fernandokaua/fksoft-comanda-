// VERSÃO FINAL - USANDO EXPRESS + POSTGRESQL

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const { Pool } = require('pg'); // <-- BIBLIOTECA DO POSTGRESQL

const app = express();
const port = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// --- Conexão com o Banco de Dados PostgreSQL ---
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'fksoft_db', // O banco de dados que criamos
    password: '12345',      // A senha que você definiu
    port: 5432,
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
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                usuario TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS estoque (
                id SERIAL PRIMARY KEY,
                codigo TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                preco REAL NOT NULL,
                quantidade INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vendas (
                id SERIAL PRIMARY KEY,
                produto_nome TEXT NOT NULL,
                produto_preco REAL NOT NULL,
                metodo_pagamento TEXT NOT NULL,
                desconto REAL DEFAULT 0,
                data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS compras (
                id SERIAL PRIMARY KEY,
                produto TEXT NOT NULL,
                valor REAL NOT NULL,
                metodo_pagamento TEXT NOT NULL,
                data_compra DATE NOT NULL
            );
        `);

        // Inserir usuário admin padrão se não existir
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

// Executa a função de setup ao iniciar e só então inicia o servidor
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

        if (!user) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const match = await bcrypt.compare(senha, user.senha);
        if (match) {
            res.json({ message: "Login bem-sucedido", role: user.role });
        } else {
            res.status(401).json({ error: "Senha incorreta" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ROTAS DE ESTOQUE
app.get('/api/estoque', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM estoque ORDER BY nome');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/estoque', async (req, res) => {
    try {
        const { codigo, nome, preco, quantidade } = req.body;
        const query = `
            INSERT INTO estoque (codigo, nome, preco, quantidade) 
            VALUES ($1, $2, $3, $4) 
            ON CONFLICT (codigo) 
            DO UPDATE SET quantidade = estoque.quantidade + $4, preco = $3
        `;
        await pool.query(query, [codigo, nome, parseFloat(preco), parseInt(quantidade)]);
        res.status(201).json({ message: "Produto adicionado/atualizado!" });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// ROTAS DE RELATÓRIOS E VENDAS (Exemplos)
app.get('/api/relatorios/vendas', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM vendas ORDER BY data_venda DESC');
        res.json(result.rows);
    } catch(err) {
        res.status(500).json({error: err.message});
    }
});

app.post('/api/vendas', async (req, res) => {
    const { itens, metodoPagamento, desconto } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Inicia a transação

        const insertVendaQuery = "INSERT INTO vendas (produto_nome, produto_preco, metodo_pagamento, desconto) VALUES ($1, $2, $3, $4)";
        const updateEstoqueQuery = "UPDATE estoque SET quantidade = quantidade - 1 WHERE codigo = $1 AND quantidade > 0";
        const descontoPorItem = (desconto / itens.length) || 0;

        for (const item of itens) {
            await client.query(insertVendaQuery, [item.nome, item.preco, metodoPagamento, descontoPorItem]);
            const estoqueResult = await client.query(updateEstoqueQuery, [item.codigo]);
            if (estoqueResult.rowCount === 0) {
                throw new Error(`Estoque insuficiente para o produto ${item.nome}`);
            }
        }

        await client.query('COMMIT'); // Finaliza a transação com sucesso
        res.status(201).json({message: "Vendas registradas e estoque atualizado!"});

    } catch (err) {
        await client.query('ROLLBACK'); // Desfaz a transação em caso de erro
        res.status(500).json({error: "Erro ao registrar vendas: " + err.message});
    } finally {
        client.release(); // Libera a conexão
    }
});

// ... Adicionar as outras rotas (compras, dashboard) convertidas para async/await e pool.query

// Servir arquivos estáticos do frontend (deve vir depois das rotas da API)
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});