# Auth

## Com docker
```bash
docker build -t registry.deti/cellwatch/auth_app:v2 .
docker push registry.deti/cellwatch/auth_app:v2
docker compose up
```

## Localmente
### Iniciar virtual env
```source venv2/bin/activate```

### Instalar requirements
``` pip install -r requirements.txt```

### Iniciar 
```python3 run.py```


## Se for a primeira vez
### Iniciar postgres
```bash
sudo su - postgres
psql
```

### Criar base de dados

```sql
CREATE DATABASE cellwatch;
```

### Criar user

``` sql
CREATE USER admin WITH PASSWORD 'admin';
```

### Dar permições

``` sql
GRANT ALL PRIVILEGES ON DATABASE cellwatch TO admin;
```


