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
## crear user

``` sql
CREATE USER admin WITH PASSWORD 'admin';
```

## dar permicoes

``` sql
GRANT ALL PRIVILEGES ON DATABASE cellwatch TO admin;
```



