rm abpvss.txt
rm scrapeDBS.txt
rm scrapeDDH.txt
rm Albatross.txt
rm HEPVSS.txt
rm dabe.txt
rm dabe11.txt
rm dabe15.txt

for i in $(seq 100 100 900); do
    sed -i "s/^N = .*/N = $i/" setting.py    
    python3 dabe.py 2 >> dabe.txt
    sleep 2
    python3 dabe11.py 2 >> dabe11.txt
    sleep 2
    python3 dabe15.py 2 >> dabe15.txt
    sleep 2
    python3 abpvss.py 2 >> abpvss.txt
    sleep 2
    python3 scrapeDBS.py >> scrapeDBS.txt
    sleep 2
    python3 scrapeDDH.py >> scrapeDDH.txt
    sleep 2
    python3 Albatross.py >> Albatross.txt
    sleep 2
    python3 HEPVSS.py >> HEPVSS.txt
    sleep 2
done
