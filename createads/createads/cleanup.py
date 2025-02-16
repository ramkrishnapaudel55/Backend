import os
import shutil


def delete_migration_files():
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            if d == 'migrations':
                migration_dir = os.path.join(root, d)
                for file in os.listdir(migration_dir):
                    if file != '__init__.py':
                        file_path = os.path.join(migration_dir, file)
                        os.remove(file_path)
                print(f"Deleted migration files in {migration_dir}")


def delete_pyc_files():
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.pyc'):
                file_path = os.path.join(root, file)
                os.remove(file_path)
                print(f"Deleted {file_path}")


def delete_pycache_dirs():
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            if d == '__pycache__':
                pycache_dir = os.path.join(root, d)
                shutil.rmtree(pycache_dir)
                print(f"Deleted {pycache_dir}")


if __name__ == "__main__":
    delete_migration_files()
    delete_pyc_files()
    delete_pycache_dirs()
