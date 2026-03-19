<?php
session_start();
if (!isset($_SESSION["ruolo"]) || $_SESSION["ruolo"] !== 'admin') {
    header("Location: ../../index.php");
    exit();
}
// --- CONFIGURAZIONE DATABASE ---
require_once __DIR__ . '/../config.php';
$conn = get_mysqli();

// Genera CSRF token
csrf_token();

// --- SICUREZZA TABELLA ---
$allowed = ['SB_categoria', 'SB_prodotto', 'SB_utente'];
$tabella = $_GET['tabella'] ?? 'SB_prodotto';
if (!in_array($tabella, $allowed)) {
    die("Tabella non valida");
}

$message = "";

// --- WHITELIST COLONNE PK PER TABELLA (VULN-01 fix) ---
$allowed_cols = [
    'SB_categoria' => 'id_categoria',
    'SB_prodotto' => 'id_prodotto',
    'SB_utente' => 'id_utente',
];

$options_cat = [];
$res_cat = $conn->query("SELECT id_categoria, descrizione FROM SB_categoria ORDER BY descrizione ASC");
if ($res_cat)
    while ($c = $res_cat->fetch_assoc())
        $options_cat[] = $c;

// --- 2. LOGICA DELETE (spostata nel blocco POST per protezione CSRF) ---

// --- 3. LOGICA INSERT / UPDATE ---
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    csrf_verify(); // VULN-05: verifica CSRF token
    $azione = $_POST['azione'] ?? '';
    $success = false;
    $executed = false;

    // --- LOGICA DELETE (protetta da CSRF via POST) ---
    if ($azione == 'delete') {
        $id_col = $allowed_cols[$tabella];
        $id_val = intval($_POST['delete_id']);
        $stmt_del = $conn->prepare("DELETE FROM $tabella WHERE $id_col = ?");
        $stmt_del->bind_param("i", $id_val);
        if ($stmt_del->execute()) {
            $message = "<div class='alert alert-success'>Eliminato con successo!</div>";
        } else {
            $message = "<div class='alert alert-error'>Errore: " . $conn->error . "</div>";
        }
        $stmt_del->close();
    }

    if ($tabella == 'SB_categoria') {
        $desc = trim($_POST['descrizione']);

        if ($azione == 'add') {
            $check = $conn->prepare("SELECT id_categoria FROM SB_categoria WHERE descrizione = ? LIMIT 1");
            $check->bind_param("s", $desc);
            $check->execute();
            $check->store_result();
            if ($check->num_rows > 0) {
                $message = "<div class='alert alert-warning'>La categoria \"" . htmlspecialchars($desc) . "\" esiste già!</div>";
            } else {
                $stmt = $conn->prepare("INSERT INTO SB_categoria (descrizione) VALUES (?)");
                $stmt->bind_param("s", $desc);
                $success = $stmt->execute();
                $stmt->close();
                $executed = true;
            }
            $check->close();
        } else {
            $id = intval($_POST['id']);
            $stmt = $conn->prepare("UPDATE SB_categoria SET descrizione=? WHERE id_categoria=?");
            $stmt->bind_param("si", $desc, $id);
            $success = $stmt->execute();
            $stmt->close();
            $executed = true;
        }

    } elseif ($tabella == 'SB_prodotto') {
        $nome = trim($_POST['nome']);
        $desc_prod = trim($_POST['descrizione']);
        $prezzo = floatval($_POST['prezzo']);
        $cat = intval($_POST['id_categoria']);
        $giacenza = intval($_POST['giacenza']);

        if ($azione == 'add') {
            $stmt = $conn->prepare("INSERT INTO SB_prodotto (nome, descrizione, prezzo, id_categoria, giacenza) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("ssdii", $nome, $desc_prod, $prezzo, $cat, $giacenza);
        } else {
            $id = intval($_POST['id']);
            $stmt = $conn->prepare("UPDATE SB_prodotto SET nome=?, descrizione=?, prezzo=?, id_categoria=?, giacenza=? WHERE id_prodotto=?");
            $stmt->bind_param("ssdiis", $nome, $desc_prod, $prezzo, $cat, $giacenza, $id);
        }
        $success = $stmt->execute();
        $stmt->close();
        $executed = true;

    } elseif ($tabella == 'SB_utente') {
        $username = trim($_POST['username']);
        $email = trim($_POST['email']);
        $ruolo = trim($_POST['ruolo']);
        $nome = trim($_POST['nome'] ?? '');
        $cognome = trim($_POST['cognome'] ?? '');
        $saldo = floatval($_POST['saldo'] ?? 0);

        if ($azione == 'add') {
            $password_plain = $_POST['password'] ?? '';
            $password_hash = password_hash($password_plain, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO SB_utente (username, email, ruolo, password_hash, nome, cognome, saldo) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssssd", $username, $email, $ruolo, $password_hash, $nome, $cognome, $saldo);
        } else {
            $id = intval($_POST['id']);
            $stmt = $conn->prepare("UPDATE SB_utente SET username=?, email=?, ruolo=?, nome=?, cognome=?, saldo=? WHERE id_utente=?");
            $stmt->bind_param("sssssdi", $username, $email, $ruolo, $nome, $cognome, $saldo, $id);
        }
        $success = $stmt->execute();
        $stmt->close();
        $executed = true;
    }

    if ($executed && $success) {
        $message = "<div class='alert alert-success'>Operazione riuscita!</div>";
    } elseif ($executed) {
        $message = "<div class='alert alert-error'>Errore: " . $conn->error . "</div>";
    }
}

// --- 4. RECUPERO DATI PER LA TABELLA ---
if ($tabella == 'SB_prodotto') {
    $query_sql = "SELECT p.id_prodotto, p.nome, p.descrizione, p.prezzo,
                  c.descrizione AS categoria, p.giacenza, p.id_categoria
                  FROM SB_prodotto p
                  LEFT JOIN SB_categoria c ON p.id_categoria = c.id_categoria";
} elseif ($tabella == 'SB_utente') {
    $query_sql = "SELECT id_utente, nome, cognome, username, email, ruolo, saldo FROM SB_utente";
} else {
    $query_sql = "SELECT * FROM $tabella";
}

$query_tabella = $conn->query($query_sql);
if (!$query_tabella)
    die("Errore query: " . $conn->error . "<br>Query: " . $query_sql);

$campi = $query_tabella->fetch_fields();

// --- 5. CONTEGGIO PRODOTTI PER CATEGORIA (per alert JS) ---
$prodotti_per_categoria = [];
$res_count = $conn->query("SELECT id_categoria, COUNT(*) AS totale FROM SB_prodotto GROUP BY id_categoria");
if ($res_count) {
    while ($r = $res_count->fetch_assoc()) {
        $prodotti_per_categoria[$r['id_categoria']] = (int) $r['totale'];
    }
}
?>

<!DOCTYPE html>
<html lang="it">

<head>
    <meta charset="UTF-8">
    <title>SpeedyBreak Admin</title>
    <link rel="stylesheet" href="../../Assets/Styles/style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .admin-layout {
            display: flex;
            min-height: calc(100vh - 70px);
            align-items: stretch;
        }

        .admin-sidebar {
            width: 250px;
            background: var(--color-surface);
            border-right: 1px solid var(--color-border);
            padding: var(--space-6) var(--space-4);
        }

        .admin-main {
            flex: 1;
            padding: var(--space-6);
            background: var(--color-bg);
            overflow-x: auto;
        }

        .sidebar-link {
            display: block;
            padding: 10px 16px;
            color: var(--color-text-muted);
            text-decoration: none;
            border-radius: var(--radius-md);
            margin-bottom: var(--space-2);
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .sidebar-link:hover {
            background: var(--color-border);
            color: var(--color-text);
        }

        .sidebar-link.active {
            background: var(--color-primary-light);
            color: var(--color-primary);
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: flex-start;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
            overflow-y: auto;
            padding: var(--space-4);
            box-sizing: border-box;
        }

        .modal-overlay.show {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-content {
            background: var(--color-surface);
            padding: var(--space-6);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 500px;
            box-shadow: var(--shadow-xl);
            transform: translateY(-20px);
            transition: transform 0.2s ease;
            max-height: 90vh;
            overflow-y: auto;
            margin: auto;
        }

        .modal-overlay.show .modal-content {
            transform: translateY(0);
        }

        /* Table Styles */
        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: var(--font-size-sm);
        }

        .table th {
            text-align: left;
            padding: var(--space-3);
            border-bottom: 2px solid var(--color-border);
            color: var(--color-text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .table td {
            padding: var(--space-3);
            border-bottom: 1px solid var(--color-border);
            color: var(--color-text);
        }

        .table tr:hover {
            background: var(--color-bg);
        }
    </style>
</head>

<body>

    <nav class="navbar">
        <div class="nav-container container">
            <a href="../../index.php" class="brand">
                <img src="../../Assets/Images/logo.png" alt="Logo Speedy Break">
                <span>Speedy Break</span>
            </a>
            <ul class="nav-links">
                <li><a class="nav-item" href="../../index.php">Home</a></li>
                <li><a class="nav-item" href="../creazione_ordine/index_order.php">Ordina</a></li>
                <li><a class="nav-item" href="../ordini/my_ordini.php">I Miei Ordini</a></li>

                <?php if (isset($_SESSION["ruolo"]) && ($_SESSION["ruolo"] === 'admin' || $_SESSION["ruolo"] === 'barista')): ?>
                    <li><a class="nav-item" href="../gestione_ordini/manage.php">Gestione Ordini</a></li>
                <?php endif; ?>

                <?php if (isset($_SESSION["ruolo"]) && $_SESSION["ruolo"] === 'admin'): ?>
                    <li><a class="nav-item active" href="admin.php">Admin</a></li>
                <?php endif; ?>
                <li><a class="nav-item" href="statistiche.php">Statistiche</a></li>

                <li>
                    <?php if (isset($_SESSION["user_id"])): ?>
                        <a class="nav-icon-btn" href="../auth/profile.php" title="Area Personale">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                <circle cx="12" cy="7" r="4"></circle>
                            </svg>
                        </a>
                    <?php else: ?>
                        <a class="nav-icon-btn" href="../auth/login.php" title="Login">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
                                <polyline points="10 17 15 12 10 7"></polyline>
                                <line x1="15" y1="12" x2="3" y2="12"></line>
                            </svg>
                        </a>
                    <?php endif; ?>
                </li>
            </ul>
        </div>
    </nav>

    <div class="admin-layout">
        <!-- Sidebar -->
        <aside class="admin-sidebar">
            <h3
                style="font-size: var(--font-size-lg); font-weight: 700; margin-bottom: var(--space-6); color: var(--color-secondary);">
                Dashboard</h3>
            <div class="flex flex-col">
                <a href="?tabella=SB_categoria"
                    class="sidebar-link <?= $tabella == 'SB_categoria' ? 'active' : '' ?>">Categorie</a>
                <a href="?tabella=SB_prodotto"
                    class="sidebar-link <?= $tabella == 'SB_prodotto' ? 'active' : '' ?>">Prodotti</a>
                <a href="?tabella=SB_utente"
                    class="sidebar-link <?= $tabella == 'SB_utente' ? 'active' : '' ?>">Utenti</a>
            </div>
        </aside>

        <!-- Main content -->
        <main class="admin-main">
            <div class="mb-4">
                <?= $message ?>
            </div>

            <div class="flex justify-between items-center mb-6">
                <h2 style="font-size: var(--font-size-2xl);">Tabella: <?= str_replace('SB_', '', $tabella) ?></h2>
                <button class="btn btn-primary" onclick="apriModalAggiungi()">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                        style="margin-right: 4px;">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                    Aggiungi
                </button>
            </div>

            <div class="card" style="padding: 0; overflow: hidden; overflow-x: auto;">
                <table class="table">
                    <thead>
                        <tr>
                            <?php
                            foreach ($campi as $f) {
                                if (in_array($f->name, ['id_categoria', 'id_utente', 'id_prodotto']))
                                    continue;
                                echo "<th>" . htmlspecialchars(ucfirst($f->name)) . "</th>";
                            }
                            ?>
                            <th style="width: 120px; text-align: center;">Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $query_tabella->fetch_assoc()):
                            $pk = $campi[0]->name;
                            $json_data = htmlspecialchars(json_encode($row));
                            ?>
                            <tr>
                                <?php foreach ($campi as $f):
                                    if (in_array($f->name, ['id_categoria', 'id_utente', 'id_prodotto']))
                                        continue;
                                    ?>
                                    <td><?= htmlspecialchars($row[$f->name] ?? '') ?></td>
                                <?php endforeach; ?>
                                <td style="text-align: center;">
                                    <div class="flex justify-center gap-2">
                                        <button class="btn btn-secondary" style="padding: 6px;"
                                            onclick='apriModalModifica(<?= $json_data ?>)' title="Modifica">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                                                stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                                stroke-linejoin="round">
                                                <path d="M12 20h9"></path>
                                                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
                                            </svg>
                                        </button>
                                        <?php
                                        $extra = '';
                                        if ($tabella === 'SB_categoria') {
                                            $id_cat = $row[$pk];
                                            $num_prod = $prodotti_per_categoria[$id_cat] ?? 0;
                                            $extra = "data-num-prodotti=\"$num_prod\"";
                                        }
                                        ?>
                                        <form method="POST" class="form-elimina" style="display:inline;"
                                            data-tabella="<?= $tabella ?>" <?= $extra ?>>
                                            <?= csrf_field() ?>
                                            <input type="hidden" name="azione" value="delete">
                                            <input type="hidden" name="delete_id" value="<?= $row[$pk] ?>">
                                            <button type="submit" class="btn btn-danger btn-elimina" style="padding: 6px;"
                                                title="Elimina">
                                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                                                    stroke="currentColor" stroke-width="2" stroke-linecap="round"
                                                    stroke-linejoin="round">
                                                    <polyline points="3 6 5 6 21 6"></polyline>
                                                    <path
                                                        d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2">
                                                    </path>
                                                </svg>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>

    <!-- MODAL CRUD -->
    <div id="crudModal" class="modal-overlay">
        <div class="modal-content">
            <form method="POST">
                <?= csrf_field() ?>
                <div class="flex justify-between items-center mb-6">
                    <h5 id="modalTitle" style="font-size: var(--font-size-xl); font-weight: 700;">Gestisci Record</h5>
                    <button type="button" class="btn btn-secondary" style="padding: 4px 8px; border-radius: 50%;"
                        onclick="chiudiModal()">✕</button>
                </div>

                <div id="modalBody" class="flex flex-col gap-4">
                    <input type="hidden" name="azione" id="formAzione">
                    <input type="hidden" name="id" id="formId">

                    <?php if ($tabella == 'SB_categoria'): ?>
                        <div class="form-group">
                            <label class="form-label">Descrizione Categoria</label>
                            <input type="text" name="descrizione" id="input_descrizione" class="form-control" required>
                        </div>

                    <?php elseif ($tabella == 'SB_prodotto'): ?>
                        <div class="form-group">
                            <label class="form-label">Nome Prodotto</label>
                            <input type="text" name="nome" id="input_nome" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Descrizione Prodotto</label>
                            <textarea name="descrizione" id="input_descrizione" class="form-control" rows="2"></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Prezzo (€)</label>
                            <input type="number" step="0.01" name="prezzo" id="input_prezzo" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Categoria</label>
                            <select name="id_categoria" id="input_id_categoria" class="form-control" required>
                                <option value="">-- Seleziona --</option>
                                <?php foreach ($options_cat as $c): ?>
                                    <option value="<?= $c['id_categoria'] ?>"><?= htmlspecialchars($c['descrizione']) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Quantità Disponibile</label>
                            <input type="number" name="giacenza" id="input_giacenza" class="form-control" required>
                        </div>

                    <?php elseif ($tabella == 'SB_utente'): ?>
                        <div class="form-group">
                            <label class="form-label">Nome</label>
                            <input type="text" name="nome" id="input_nome" class="form-control">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Cognome</label>
                            <input type="text" name="cognome" id="input_cognome" class="form-control">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" id="input_username" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Email</label>
                            <input type="email" name="email" id="input_email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Ruolo</label>
                            <select name="ruolo" id="input_ruolo" class="form-control" required>
                                <option value="customer">Customer</option>
                                <option value="barista">Barista</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <!-- Campo password: visibile solo in fase di aggiunta, nascosto in modifica -->
                        <div class="form-group" id="passwordField">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" id="input_password" class="form-control">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Saldo (€)</label>
                            <input type="number" step="0.01" min="0" name="saldo" id="input_saldo" class="form-control"
                                value="0">
                        </div>

                    <?php endif; ?>
                </div>

                <div class="flex justify-end gap-2 mt-6 pt-4" style="border-top: 1px solid var(--color-border);">
                    <button type="button" class="btn btn-secondary" onclick="chiudiModal()">Annulla</button>
                    <button type="submit" class="btn btn-primary">Salva</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const modalElement = document.getElementById('crudModal');

        function apriModalAggiungi() {
            modalElement.querySelector('form').reset();
            document.getElementById('modalTitle').innerText = "Aggiungi Nuovo";
            document.getElementById('formAzione').value = "add";
            document.getElementById('formId').value = "";

            // Mostra il campo password (solo per utenti) e lo rende obbligatorio
            const passwordField = document.getElementById('passwordField');
            if (passwordField) {
                passwordField.style.display = '';
                document.getElementById('input_password').required = true;
            }

            modalElement.classList.add('show');
        }

        function apriModalModifica(data) {
            modalElement.querySelector('form').reset();
            document.getElementById('modalTitle').innerText = "Modifica Record";
            document.getElementById('formAzione').value = "edit";

            const pkName = Object.keys(data)[0];
            document.getElementById('formId').value = data[pkName];

            for (let key in data) {
                let el = document.getElementById('input_' + key);
                if (!el) continue;
                if (el.type === 'datetime-local' && data[key]) {
                    el.value = data[key].replace(' ', 'T');
                } else {
                    el.value = data[key];
                }
            }

            // Nasconde il campo password in fase di modifica
            const passwordField = document.getElementById('passwordField');
            if (passwordField) {
                passwordField.style.display = 'none';
                document.getElementById('input_password').required = false;
            }

            modalElement.classList.add('show');
        }

        function chiudiModal() {
            modalElement.classList.remove('show');
        }

        // Chiudi il modal cliccando fuori
        modalElement.addEventListener('click', function (e) {
            if (e.target === this) {
                chiudiModal();
            }
        });

        // Alert eliminazione con conteggio prodotti per le categorie
        document.querySelectorAll('.form-elimina').forEach(function (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                const tabella = this.dataset.tabella;
                let messaggio = 'Eliminare questo record?';

                if (tabella === 'SB_categoria') {
                    const numProdotti = parseInt(this.dataset.numProdotti || '0');
                    if (numProdotti > 0) {
                        messaggio = `Attenzione! Questa categoria contiene ${numProdotti} prodott${numProdotti === 1 ? 'o' : 'i'} che verranno eliminat${numProdotti === 1 ? 'o' : 'i'} insieme ad essa.\n\nProcedere con l'eliminazione?`;
                    } else {
                        messaggio = 'Questa categoria non contiene prodotti. Eliminare?';
                    }
                }

                if (confirm(messaggio)) {
                    this.submit();
                }
            });
        });
    </script>
</body>

</html>
