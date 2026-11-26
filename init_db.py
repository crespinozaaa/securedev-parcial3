import sqlite3
from werkzeug.security import generate_password_hash

def crear_base_de_datos():
    conexion = sqlite3.connect('vulnerable.db')
    cursor = conexion.cursor()
    
    cursor.execute('DROP TABLE IF EXISTS usuarios')
    cursor.execute('''
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            rol TEXT NOT NULL,
            bio TEXT
        )
    ''')
    
    usuarios = [
        ('admin', generate_password_hash('Admin#Secure2026!'), 'admin', 'Cuenta de administrador del sistema.'),
        ('alumno', generate_password_hash('Alumno#2026!'), 'user', 'Soy un estudiante aprendiendo DevSecOps.')
    ]
    
    cursor.executemany(
        'INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)',
        usuarios
    )
    conexion.commit()
    conexion.close()
    print("Base de datos segura inicializada correctamente.")

if __name__ == "__main__":
    crear_base_de_datos()
