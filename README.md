# Auth

# com docker
```bash
docker compose up
```


## iniciar virtual env
```source venv2/bin/activate```

## instalar requirements
``` pip install -r requirements.txt```

## iniciar 
```python3 run.py```


## se for a primeira vez
### iniciar postgres

```bash
sudo su - postgres
psql
```
### criar base de dados
```sql
CREATE DATABASE cellwatch;
```

### criar user

``` sql
CREATE USER admin WITH PASSWORD 'admin';
```

### dar permições

``` sql
GRANT ALL PRIVILEGES ON DATABASE cellwatch TO admin;
```



```bash
docker build -t registry.deti/cellwatch/auth_app:v1 . 
docker push registry.deti/cellwatch/auth_app:v1
docker run -p 8080:8080 registry.deti:/cellwatch:v1
```

