from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'
bcrypt = Bcrypt(app)


# Conexão com o banco de dados
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


# Página inicial
@app.route('/')
def home():
    return render_template('landingpage.html')


# Verificar se a senha é forte
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


# Cadastrar novo usuário (somente aluno)
@app.route('/novo_usuario', methods=['GET', 'POST'])
def novo_usuario():

    # Cadastro de aluno
    tipo = 1

    if request.method == 'GET':
        return render_template('novo_usuario.html')

    nome = request.form['nome'].strip()
    email = request.form['email'].strip()
    senha = request.form['senha']
    confirmar_senha = request.form['confirmar_senha']

    # Verificar campos preenchidos
    if not nome or not email or not senha or not confirmar_senha:
        flash('Preencha todos os campos.', 'erro')
        return redirect(url_for('novo_usuario'))

    # Verificar se a senha é forte
    if not senha_forte(senha):
        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'uma letra maiúscula, uma letra minúscula, '
            'um número e um caractere especial.',
            'erro'
        )
        return redirect(url_for('novo_usuario'))

    # Verificar se as senhas são iguais
    if senha != confirmar_senha:
        flash('As senhas não são iguais.', 'erro')
        return redirect(url_for('novo_usuario'))

    cursor = con.cursor()

    try:
        # Verificar se o e-mail já está cadastrado
        cursor.execute("""
            SELECT ID_USUARIO
            FROM USUARIO
            WHERE EMAIL = ?
        """, (email,))

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            flash('Este e-mail já está cadastrado.', 'erro')
            return redirect(url_for('novo_usuario'))

        # Criptografar a senha
        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # Cadastrar o usuário como aluno (tipo 1)
        cursor.execute("""
            INSERT INTO USUARIO
                (NOME, EMAIL, SENHA, TENTATIVAS, ATIVO, TIPO)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nome, email, senha_hash, 0, 1, tipo))

        con.commit()

        flash('Usuário cadastrado com sucesso!', 'sucesso')
        return redirect(url_for('login'))

    except Exception as e:
        con.rollback()
        print('Erro ao cadastrar usuário:', repr(e))
        flash('Erro ao cadastrar usuário.', 'erro')
        return redirect(url_for('novo_usuario'))

    finally:
        cursor.close()


# Login para aluno, administrador e professor
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        # Receber os dados do formulário
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')

        # Verificar se os campos foram preenchidos
        if not email or not senha:
            flash('Preencha o e-mail e a senha.', 'erro')
            return redirect(url_for('login'))

        cursor = con.cursor()

        try:
            # Buscar o usuário pelo e-mail
            cursor.execute("""
                SELECT
                    ID_USUARIO,
                    NOME,
                    EMAIL,
                    SENHA,
                    TENTATIVAS,
                    ATIVO,
                    TIPO
                FROM USUARIO
                WHERE EMAIL = ?
            """, (email,))

            usuario = cursor.fetchone()

            # Verificar se o usuário existe
            if not usuario:
                flash('E-mail ou senha incorretos.', 'erro')
                return redirect(url_for('login'))

            # Separar os dados do usuário
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

            # Verificar se a conta está ativa
            if ativo != 1:
                flash('Usuário inativo ou bloqueado.', 'erro')
                return redirect(url_for('login'))

            # Verificar a senha
            if bcrypt.check_password_hash(senha_hash, senha):

                # Guardar os dados na sessão
                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco
                session['tipo_usuario'] = tipo

                # Zerar as tentativas
                cursor.execute("""
                    UPDATE USUARIO
                    SET TENTATIVAS = ?
                    WHERE ID_USUARIO = ?
                """, (0, id_usuario))

                con.commit()

                flash('Login realizado com sucesso!', 'sucesso')

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

                # Tipo inválido
                session.clear()
                flash('Tipo de usuário inválido.', 'erro')
                return redirect(url_for('login'))

            else:
                # Senha incorreta
                tentativas += 1

                # Bloquear depois de 3 tentativas
                if tentativas >= 3:

                    cursor.execute("""
                        UPDATE USUARIO
                        SET TENTATIVAS = ?, ATIVO = ?
                        WHERE ID_USUARIO = ?
                    """, (tentativas, 0, id_usuario))

                    con.commit()

                    flash(
                        'Usuário bloqueado após 3 tentativas.',
                        'erro'
                    )

                    return redirect(url_for('login'))

                # Atualizar o número de tentativas
                cursor.execute("""
                    UPDATE USUARIO
                    SET TENTATIVAS = ?
                    WHERE ID_USUARIO = ?
                """, (tentativas, id_usuario))

                con.commit()

                flash(
                    f'E-mail ou senha incorretos. '
                    f'Tentativa {tentativas} de 3.',
                    'erro'
                )

                return redirect(url_for('login'))

        except Exception as e:
            con.rollback()
            print('Erro no login:', repr(e))
            flash('Ocorreu um erro no login.', 'erro')
            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# Dashboard do aluno
@app.route('/inicio')
def index():

    # Verificar se está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Verificar se é aluno
    if session.get('tipo_usuario') != 1:
        flash(
            'Você não tem permissão para acessar esta página.',
            'erro'
        )
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

    if session.get('tipo_usuario') != 0:
        flash(
            'Você não tem permissão para acessar esta página.',
            'erro'
        )
        return redirect(url_for('redirecionar'))

    cursor = con.cursor()

    try:
        # Buscar o nome atualizado no banco
        cursor.execute("""
            SELECT NOME
            FROM USUARIO
            WHERE ID_USUARIO = ?
        """, (session['id_usuario'],))

        usuario = cursor.fetchone()

        if usuario is None:
            session.clear()
            return redirect(url_for('login'))

        nome = usuario[0]

        # Manter o nome da sessão atualizado
        session['usuario_nome'] = nome

        return render_template(
            'dashboard_administrador.html',
            nome=nome
        )

    except Exception as e:
        con.rollback()
        print('Erro no dashboard:', repr(e))
        flash('Não foi possível carregar o dashboard.', 'erro')
        return redirect(url_for('login'))

    finally:
        cursor.close()


# Redirecionar pelo tipo de usuário
@app.route('/redirecionar')
def redirecionar():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session['tipo_usuario']

    if tipo == 1:
        return redirect(url_for('index'))

    elif tipo == 0:
        return redirect(url_for('dashboard_administrador'))

    elif tipo == 2:
        return redirect(url_for('grade_de_aulas'))

    else:
        session.clear()
        flash('Tipo de usuário inválido.', 'erro')
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

            # Validar a senha antes de comparar a confirmação
            if senha or confirmar_senha:

                if not senha_forte(senha):
                    flash(
                        'A senha não atende aos requisitos de segurança.',
                        'erro'
                    )
                    return redirect(url_for('editar_perfil'))

                if senha != confirmar_senha:
                    flash('As senhas não são iguais.', 'erro')
                    return redirect(url_for('editar_perfil'))

            # Verificar se o e-mail pertence a outro usuário
            cursor.execute("""
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE EMAIL = ?
                  AND ID_USUARIO <> ?
            """, (email, id_usuario))

            if cursor.fetchone():
                flash('Este e-mail já está cadastrado.', 'erro')
                return redirect(url_for('editar_perfil'))

            if senha:
                senha_hash = bcrypt.generate_password_hash(
                    senha
                ).decode('utf-8')

                cursor.execute("""
                    UPDATE USUARIO
                    SET NOME = ?, EMAIL = ?, SENHA = ?
                    WHERE ID_USUARIO = ?
                """, (nome, email, senha_hash, id_usuario))

            else:
                cursor.execute("""
                    UPDATE USUARIO
                    SET NOME = ?, EMAIL = ?
                    WHERE ID_USUARIO = ?
                """, (nome, email, id_usuario))

            con.commit()

            # Atualizar os dados da sessão
            session['usuario_nome'] = nome
            session['usuario_email'] = email

            flash('Perfil atualizado com sucesso!', 'sucesso')
            return redirect(url_for('editar_perfil'))

        # Buscar os dados atuais do usuário
        cursor.execute("""
            SELECT NOME, EMAIL
            FROM USUARIO
            WHERE ID_USUARIO = ?
        """, (id_usuario,))

        usuario = cursor.fetchone()

        if not usuario:
            session.clear()
            return redirect(url_for('login'))

        return render_template(
            'editar_perfil.html',
            nome=usuario[0],
            email=usuario[1],
            tipo=tipo,
            id_usuario=id_usuario
        )

    except Exception as e:
        con.rollback()
        print('Erro ao editar perfil:', repr(e))
        flash('Não foi possível atualizar o perfil.', 'erro')
        return redirect(url_for('editar_perfil'))

    finally:
        cursor.close()


# Logout
@app.route('/logout')
def logout():

    # Encerrar a sessão do usuário
    session.clear()

    flash('Você saiu da sua conta com sucesso!', 'sucesso')
    return redirect(url_for('login'))


# Grade de aulas
@app.route('/grade_de_aulas')
def grade_de_aulas():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if session.get('tipo_usuario') not in (0, 1, 2):
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT
                A.ID_AULA,
                A.HORARIO,
                A.CAPACIDADE,
                A.ID_MODALIDADE,
                A.ID_USUARIO,
                D.DIA_SEMANA,
                H.HORARIO
            FROM AULA A
            LEFT JOIN DIA_SEMANA D
                ON D.ID_AULA = A.ID_AULA
            LEFT JOIN HORARIO H
                ON H.ID_DIA = D.ID_DIA
            ORDER BY D.DIA_SEMANA, H.HORARIO
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
        con.rollback()
        print('ERRO NA GRADE DE AULAS:', repr(e))
        flash('Não foi possível carregar a grade de aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    finally:
        cursor.close()


# Editar aula
# Administrador = 0; professor = 2
@app.route('/editar_aula/<int:id_aula>', methods=['GET', 'POST'])
def editar_aula(id_aula):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session['tipo_usuario']

    if tipo not in (0, 2):
        flash('Você não tem permissão para editar aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    # Esta rota apenas abre a página de edição.
    # O salvamento das alterações ainda precisa ser implementado.
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
        # Buscar as modalidades que já foram cadastradas
        cursor.execute("""
            SELECT ID_MODALIDADE, NOME
            FROM MODALIDADE
            ORDER BY NOME
        """)
        modalidades = cursor.fetchall()

        # Buscar os professores ativos
        cursor.execute("""
            SELECT ID_USUARIO, NOME
            FROM USUARIO
            WHERE TIPO = 2 AND ATIVO = 1
            ORDER BY NOME
        """)
        professores = cursor.fetchall()

        # Abrir a página de cadastro
        if request.method == 'GET':
            return render_template(
                'cadastrar_aula.html',
                modalidades=modalidades,
                professores=professores
            )

        # Receber os dados do formulário
        id_modalidade = request.form.get('id_modalidade', '').strip()
        horario = request.form.get('horario', '').strip()
        capacidade = request.form.get('capacidade', '').strip()
        professor = request.form.get('professor', '').strip()
        dias = request.form.getlist('dia[]')

        # Verificar os campos obrigatórios
        if not id_modalidade or not horario or not capacidade or not professor or not dias:
            flash('Preencha todos os campos obrigatórios.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Converter os valores numéricos
        try:
            id_modalidade = int(id_modalidade)
            horario = int(horario)
            capacidade = int(capacidade)
            professor = int(professor)
            dias = [int(dia) for dia in dias]
        except ValueError:
            flash('Verifique os valores selecionados.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Validar a capacidade
        if capacidade < 1 or capacidade > 18:
            flash('A capacidade deve ser entre 1 e 18 pessoas.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Validar os dias selecionados
        if any(dia < 1 or dia > 6 for dia in dias):
            flash('Foi selecionado um dia inválido.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        if len(dias) != len(set(dias)):
            flash('Não selecione o mesmo dia mais de uma vez.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Verificar se a modalidade selecionada existe
        cursor.execute("""
            SELECT ID_MODALIDADE
            FROM MODALIDADE
            WHERE ID_MODALIDADE = ?
        """, (id_modalidade,))

        if cursor.fetchone() is None:
            flash('Selecione uma modalidade válida.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Verificar se o professor existe e está ativo
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

        # Cadastrar a aula vinculada à modalidade escolhida
        cursor.execute("""
            INSERT INTO AULA
                (HORARIO, CAPACIDADE, ID_MODALIDADE, ID_USUARIO)
            VALUES (?, ?, ?, ?)
            RETURNING ID_AULA
        """, (horario, capacidade, id_modalidade, professor))

        id_aula = cursor.fetchone()[0]

        # Cadastrar os dias e seus horários
        for dia in dias:
            cursor.execute("""
                INSERT INTO DIA_SEMANA (DIA_SEMANA, ID_AULA)
                VALUES (?, ?)
                RETURNING ID_DIA
            """, (dia, id_aula))

            id_dia = cursor.fetchone()[0]

            cursor.execute("""
                INSERT INTO HORARIO (HORARIO, ID_DIA)
                VALUES (
                    DATEADD(HOUR, ?, CAST(CURRENT_DATE AS TIMESTAMP)),
                    ?
                )
            """, (horario, id_dia))

        con.commit()

        flash('Aula cadastrada com sucesso!', 'sucesso')
        return redirect(url_for('grade_de_aulas'))

    except Exception as e:
        con.rollback()
        print('ERRO AO CADASTRAR AULA:', repr(e))
        flash('Não foi possível cadastrar a aula. Confira o erro no terminal.', 'erro')
        return redirect(url_for('cadastrar_aula'))

    finally:
        cursor.close()




@app.route('/cadastrar_modalidade', methods=['GET', 'POST'])
def cadastrar_modalidade():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form['nome'].strip()
        descricao = request.form['descricao'].strip()

        if nome == '' or descricao == '':
            flash('Preencha todos os campos.', 'erro')
            return redirect(url_for('cadastrar_modalidade'))

        cursor = None

        try:
            cursor = con.cursor()

            cursor.execute("""
                INSERT INTO MODALIDADE (NOME, DESCRICAO)
                VALUES (?, ?)
            """, (nome, descricao))

            con.commit()

            flash('Modalidade cadastrada com sucesso!', 'sucesso')
            return redirect(url_for('cadastrar_aula'))

        except Exception as erro:
            con.rollback()

            # Mostra o motivo real do erro no terminal do PyCharm
            print('ERRO AO CADASTRAR MODALIDADE:', repr(erro))

            flash('Erro ao cadastrar modalidade. Confira o terminal.', 'erro')

        finally:
            if cursor is not None:
                cursor.close()

    return render_template('cadastrar_modalidade.html')

# Excluir aula
@app.route('/excluir_aula/<int:id_aula>', methods=['POST'])
def excluir_aula(id_aula):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session['tipo_usuario']

    # Somente administrador ou professor pode excluir
    if tipo not in (0, 2):
        flash('Você não tem permissão para excluir aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    cursor = con.cursor()

    try:
        # Verificar se a aula existe e quem é o professor responsável
        cursor.execute("""
            SELECT ID_USUARIO
            FROM AULA
            WHERE ID_AULA = ?
        """, (id_aula,))

        aula = cursor.fetchone()

        if aula is None:
            flash('A aula não foi encontrada.', 'erro')
            return redirect(url_for('grade_de_aulas'))

        # Professor só pode excluir a própria aula
        if tipo == 2 and aula[0] != session['id_usuario']:
            flash('Você só pode excluir as aulas sob sua responsabilidade.','erro' )
            return redirect(url_for('grade_de_aulas'))

        # Verificar se existem inscrições relacionadas à aula
        cursor.execute("""
            SELECT COUNT(*)
            FROM INSCRICAO
            WHERE ID_AULA = ?
        """, (id_aula,))

        inscricoes = cursor.fetchone()[0]

        if inscricoes > 0:
            flash('Não é possível excluir esta aula porque existem ''inscrições vinculadas.','erro')
            return redirect(url_for('grade_de_aulas'))

        # Buscar os dias cadastrados para a aula
        cursor.execute("""
            SELECT ID_DIA
            FROM DIA_SEMANA
            WHERE ID_AULA = ?
        """, (id_aula,))

        dias = cursor.fetchall()

        # Excluir os horários relacionados a cada dia
        for dia in dias:
            cursor.execute("""
                DELETE FROM HORARIO
                WHERE ID_DIA = ?
            """, (dia[0],))

        # Excluir os dias relacionados à aula
        cursor.execute("""
            DELETE FROM DIA_SEMANA
            WHERE ID_AULA = ?
        """, (id_aula,))

        # Excluir a aula
        cursor.execute("""
            DELETE FROM AULA
            WHERE ID_AULA = ?
        """, (id_aula,))

        con.commit()

        flash('Aula excluída com sucesso!', 'sucesso')

    except Exception as e:
        con.rollback()
        print('Erro ao excluir aula:', repr(e))
        flash('Erro ao excluir a aula.', 'erro')

    finally:
        cursor.close()

    return redirect(url_for('grade_de_aulas'))


if __name__ == '__main__':
    app.run(debug=True)
