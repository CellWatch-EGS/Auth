# Auth

# iniciar virtual env
```source venv2/bin/activate```

# instalar requirements
``` pip install -r requirements.txt```

# iniciar 
```python3 run.py```


# se for a primeira vez
## iniciar postgres

```bash
sudo su - postgres
psql
```
## criar base de dados
```sql
CREATE DATABASE cellwatch;
```

## criar user

``` sql
CREATE USER admin WITH PASSWORD 'admin';
```

## dar permições

``` sql
GRANT ALL PRIVILEGES ON DATABASE cellwatch TO admin;
```



