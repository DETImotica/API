import multiprocessing

workers = multiprocessing.cpu_count()*2+1
worker_class = "gthread"
worker_connections = 1000
threads = multiprocessing.cpu_count() + 2
certfile = "cert.pem"
keyfile = "key.pem"
accesslog = '-'
access_log_format = '%({X-Forwarded-For}i)s -> %(h)s: %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
errorlog = '-'
capture_output = True
bind = "0.0.0.0:25000"
