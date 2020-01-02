#make config.json

./pep3.py run all &
peppid=$!

./webdemo_monitor.py &
monitorid=$!

FLASK_APP=webdemo.py FLASK_ENV=development ./webdemo.py


kill -KILL $monitorid
kill -KILL $peppid


