from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'
bcrypt = Bcrypt(app)


# Conexao com o banco de dados
host = 'localhost'
database = r'C:\Users\Aluno\Downloads\BancoDados\TRABALHOATFIT.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# Pagina inicial
@app.route('/')
def home():
    return render_template('landingpage.html')


# verificar se a senha e forte
def senha_forte(senha):
    if len(senha) < 8:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:

        if caractere.isupper():
            tem_maiuscula = True

        elif caractere.islower():
            tem_minuscula = True

        elif caractere.isdigit():
            tem_numero = True

        else:
            tem_especial = True

    return (
        tem_maiuscula
        and tem_minuscula
        and tem_numero
        and tem_especial
    )


# Cadastrar novo usuario (somente aluno)
@app.route('/novo_usuario', methods=['GET', 'POST'])
def novo_usuario():

    # cadastro aluno
    tipo = 1

    if request.method == 'GET':
        return render_template('novo_usuario.html')

    nome = request.form['nome'].strip()
    print(nome)
    email = request.form['email'].strip()
    senha = request.form['senha']
    confirmar_senha = request.form['confirmar_senha']


    # verificar campos preenchidos

    # verificar senha igual
    if senha != confirmar_senha:
        flash('As senhas nao sao iguais.', 'erro')
        return redirect(url_for('novo_usuario'))

    #  senha forte
    if not senha_forte(senha):
        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'uma letra maiuscula, uma letra minuscula, '
            'um numero e um caractere especial.',
            'erro'
        )
        return redirect(url_for('novo_usuario'))

    cursor = con.cursor()

    try:

        # Verificar email cadastrado
        cursor.execute(
            """
            SELECT id_usuario
            FROM USUARIO
            WHERE email = ?
            """,
            (email,)
        )

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            flash('Este e-mail ja esta cadastrado.', 'erro')
            return redirect(url_for('novo_usuario'))

        # Criptografar a senha
        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # Cadastrar o usuario como aluno (tipo 1)
        cursor.execute(
            """
            INSERT INTO USUARIO
                (nome, email, senha, tentativas, ativo, tipo)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (nome, email, senha_hash, 0, 1, tipo)
        )

        con.commit()

        flash('Usuario cadastrado com sucesso!', 'sucesso')
        return redirect(url_for('login'))

    except Exception as e:
        con.rollback()
        print('Erro ao cadastrar usuario:', e)
        flash('Erro ao cadastrar usuario.', 'erro')
        return redirect(url_for('novo_usuario'))

    finally:
        cursor.close()



# Login para aluno, administrador e professor
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        # Receber os dados do formulario
        email = request.form['email'].strip()
        senha = request.form['senha']

        # Verificar se os campos foram preenchidos
        if not email or not senha:
            flash('Preencha o email e a senha.', 'erro')
            return redirect(url_for('login'))


        cursor = con.cursor()

        try:
            # Buscar o usuario pelo email
            cursor.execute(
                """
                SELECT id_usuario,nome,email,senha,tentativas,ativo,tipo
                FROM USUARIO
                WHERE email = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            # Verificar se o usuario existe
            if not usuario:
                flash('Email ou senha incorretos.', 'erro')
                return redirect(url_for('login'))

            # Separar os dados do usuario
            (
                id_usuario,
                nome,
                email_banco,
                senha_hash,
                tentativas,
                ativo,
                tipo
            ) = usuario

            if tentativas is None:
                tentativas = 0

            # Verificar se a conta esta ativa
            if ativo == 0:
                flash('Usuario inativo ou bloqueado.', 'erro')
                return redirect(url_for('login'))

            # Verificar a senha
            if bcrypt.check_password_hash(senha_hash, senha):


                # Guardar os dados na sessao
                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco
                session['tipo_usuario'] = tipo

                # Zerar as tentativas
                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET tentativas = ?
                    WHERE id_usuario = ?
                    """,
                    (0, id_usuario)
                )

                con.commit()

                # ALUNO: tipo 1
                if tipo == 1:
                    return redirect(url_for('index'))

                # ADMINISTRADOR: tipo 0
                elif tipo == 0:
                    return redirect(
                        url_for('dashboard_administrador')
                    )

                # PROFESSOR: tipo 2
                elif tipo == 2:
                    return redirect(url_for('grade_de_aulas'))

                flash('Login realizado com sucesso!', 'sucesso')



            else:
                if tipo != 0:
                    # Senha incorreta
                    tentativas += 1

                    # Bloquear depois de 3 tentativas
                    if tentativas >= 3:

                        cursor.execute(
                            """
                            UPDATE USUARIO
                            SET tentativas = ?, ativo = ?
                            WHERE id_usuario = ?
                            """,
                            (tentativas, 0, id_usuario)
                        )

                        con.commit()

                        flash(
                            'Usuario bloqueado apos 3 tentativas.',
                            'erro'
                        )

                        return redirect(url_for('login'))

                    # Atualizar o numero de tentativas
                    cursor.execute(
                        """
                        UPDATE USUARIO
                        SET tentativas = ?
                        WHERE id_usuario = ?
                        """,
                        (tentativas, id_usuario)
                    )

                    con.commit()

                    flash(
                        f'Email ou senha incorretos. '
                        f'Tentativa {tentativas} de 3.',
                        'erro'
                    )

                    return redirect(url_for('login'))
                else:
                    flash(f'Email ou senha incorretos. ')
                    return redirect(url_for('login'))

        except Exception as e:
            con.rollback()
            print('Erro no login:', e)
            flash('Ocorreu um erro no login.', 'erro')
            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# Dashboard do aluno
@app.route('/inicio')
def index():

    # Verificar se esta logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Verificar se é aluno
    if session['tipo_usuario'] != 1:
        flash('Voce não tem permissao para acessar esta pagina.', 'erro')
        return redirect(url_for('redirecionar'))

    nome = session['usuario_nome']

    return render_template(
        'dashboard.html',
        nome=nome
    )


# Dashboard do administrador
@app.route('/dashboard_administrador')
def dashboard_administrador():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if session['tipo_usuario'] != 0:
        flash('Voce nao tem permissao para acessar esta pagina.', 'erro')
        return redirect(url_for('redirecionar'))

    cursor = con.cursor()

    try:
        # Buscar o nome atualizado no banco
        cursor.execute(
            """
            SELECT nome
            FROM USUARIO
            WHERE id_usuario = ?
            """,
            (session['id_usuario'],)
        )

        usuario = cursor.fetchone()

        if usuario is None:
            return redirect(url_for('login'))

        nome = usuario[0]

        # Manter o nome da sessao atualizado
        session['usuario_nome'] = nome

        return render_template(
            'dashboard_administrador.html',
            nome=nome
        )

    except Exception:
        con.rollback()
        flash('Nao foi possivel carregar o dashboard.', 'erro')
        return redirect(url_for('login'))

    finally:
        cursor.close()

# Redirecionar pelo o tipo de usuario
@app.route('/redirecionar')
def redirecionar():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session.get('tipo_usuario')

    if tipo == 1:
        return redirect(url_for('index'))

    elif tipo == 0:
        return redirect(url_for('dashboard_administrador'))

    elif tipo == 2:
        return redirect(url_for('grade_de_aulas'))

    else:
        print(tipo)
        flash('Tipo de usuario invalido.', 'erro')
        return redirect(url_for('login'))


# Editar perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
def editar_perfil():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session['tipo_usuario']

    if tipo not in (0, 1, 2):
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        if request.method == 'POST':
            nome = request.form['nome'].strip()
            email = request.form['email'].strip()
            senha = request.form['senha']
            confirmar_senha = request.form['confirmar_senha']

            if not nome or not email:
                flash('Preencha o nome e o e-mail.', 'erro')
                return redirect(url_for('editar_perfil'))

            if senha or confirmar_senha:
                if senha != confirmar_senha:
                    flash('As senhas nao sao iguais.', 'erro')
                    return redirect(url_for('editar_perfil'))

                if not senha_forte(senha):
                    flash('A senha nao atende aos requisitos de seguranca.', 'erro')
                    return redirect(url_for('editar_perfil'))

            cursor.execute("""
                SELECT id_usuario FROM USUARIO
                WHERE email = ? AND id_usuario <> ?
            """, (email, id_usuario))

            if cursor.fetchone():
                flash('Este e-mail ja esta cadastrado.', 'erro')
                return redirect(url_for('editar_perfil'))

            if senha:
                senha = bcrypt.generate_password_hash(senha).decode('utf-8')
                cursor.execute("""
                    UPDATE USUARIO
                    SET nome = ?, email = ?, senha = ?
                    WHERE id_usuario = ?
                """, (nome, email, senha, id_usuario))
            else:
                cursor.execute("""
                    UPDATE USUARIO
                    SET nome = ?, email = ?
                    WHERE id_usuario = ?
                """, (nome, email, id_usuario))

            con.commit()
            session['usuario_nome'] = nome
            session['usuario_email'] = email

            flash('Perfil atualizado com sucesso!', 'sucesso')
            return redirect(url_for('editar_perfil'))

        cursor.execute("""
            SELECT nome, email FROM USUARIO
            WHERE id_usuario = ?
        """, (id_usuario,))

        usuario = cursor.fetchone()

        if not usuario:
            return redirect(url_for('login'))

        return render_template(
            'editar_perfil.html',
            nome=usuario[0],
            email=usuario[1],
            tipo=tipo,
            id_usuario=id_usuario
        )

    except Exception:
        con.rollback()
        flash('Nao foi possivel atualizar o perfil.', 'erro')
        return redirect(url_for('editar_perfil'))

    finally:
        cursor.close()

# Logout
@app.route('/logout')
def logout():
    flash('Voce saiu da sua conta com sucesso!', 'sucesso')
    return redirect(url_for('login'))


# Grade de aulas
@app.route('/grade_de_aulas')
def grade_de_aulas():
    print('entrei')

    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT ID_AULA, HORARIO, CAPACIDADE, ID_MODALIDADE, ID_USUARIO
            FROM AULA
            ORDER BY DIA, HORARIO
        """)
        aulas = cursor.fetchall()

        return render_template(
            'grade_de_aulas.html',
            nome=session['usuario_nome'],
            tipo=session['tipo_usuario'],
            id_usuario=session['id_usuario'],
            aulas=aulas
        )

    except Exception as e:
        print('Erro ao carregar aulas:', e)
        flash('Erro ao carregar as aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    finally:
        cursor.close()


# Editar aula
# administrador - 0  professor -2
@app.route('/editar_aula/<int:id_aula>', methods=['GET', 'POST'])
def editar_aula(id_aula):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session.get('tipo_usuario')

    if tipo != 0 and tipo != 2:
        flash('Voce nao tem permissao para editar aulas.', 'erro')
        return redirect(url_for('redirecionar'))



    return render_template(
        'editar_aula.html',
        id_aula=id_aula,
        tipo=tipo,
        id_usuario=session['id_usuario']
    )




# Cadastrar aula
@app.route('/cadastrar_aula', methods=['GET', 'POST'])
def cadastrar_aula():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Somente administrador pode cadastrar aulas
    if session.get('tipo_usuario') != 0:
        flash('Você não tem permissão para cadastrar aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    cursor = con.cursor()

    try:
        # Buscar os professores cadastrados no banco
        cursor.execute("""
            SELECT ID_USUARIO, NOME
            FROM USUARIO
            WHERE TIPO = 2
              AND ATIVO = 1
            ORDER BY NOME
        """)

        professores = cursor.fetchall()

        if request.method == 'GET':
            return render_template(
                'cadastrar_aula.html',
                professores=professores
            )

        # Receber os dados do formulário
        horario = request.form['horario'].strip()
        capacidade = request.form['capacidade'].strip()
        modalidade = request.form['modalidade'].strip()
        professor = request.form['professor'].strip()


        # Validar os campos
        if not horario or not capacidade or not modalidade or not professor:
            flash('Preencha todos os campos obrigatórios.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Validar os valores numéricos
        try:
            capacidade = int(capacidade)
            modalidade = int(modalidade)
            professor = int(professor)
        except ValueError:
            flash('Modalidade, professor e capacidade devem ser válidos.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        if capacidade < 1 or capacidade > 18:
            flash('A capacidade deve ser entre 1 e 18 pessoas.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Verificar se o professor existe e é um professor ativo
        cursor.execute("""
            SELECT ID_USUARIO
            FROM USUARIO
            WHERE ID_USUARIO = ?
              AND TIPO = 2
              AND ATIVO = 1
        """, (professor,))

        if cursor.fetchone() is None:
            flash('O professor selecionado não existe ou está inativo.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Verificar se já existe aula com a mesma modalidade,
        # horário e professor
        cursor.execute("""
            SELECT ID_AULA
            FROM AULA
            WHERE HORARIO = ?
              AND ID_MODALIDADE = ?
              AND ID_USUARIO = ?
        """, (horario, modalidade, professor))

        if cursor.fetchone():
            flash(
                'Já existe uma aula dessa modalidade, '
                'nesse horário e com esse professor.',
                'erro'
            )
            return redirect(url_for('cadastrar_aula'))

        # Inserir usando apenas as colunas existentes na tabela AULA
        cursor.execute("""
            INSERT INTO AULA
                (HORARIO, CAPACIDADE, ID_MODALIDADE, ID_USUARIO)
            VALUES (?, ?, ?, ?)
        """, (
            horario,
            capacidade,
            modalidade,
            professor
        ))

        con.commit()

        flash('Aula cadastrada com sucesso!', 'sucesso')
        return redirect(url_for('grade_de_aulas'))

    except Exception as e:
        con.rollback()

        # Mostrar o erro completo no terminal
        print('ERRO AO CADASTRAR AULA:', repr(e))

        flash(
            'Não foi possível cadastrar a aula. '
            'Verifique o erro no terminal.',
            'erro'
        )

        return redirect(url_for('cadastrar_aula'))

    finally:
        cursor.close()



if __name__ == '__main__':
    app.run(debug=True)
