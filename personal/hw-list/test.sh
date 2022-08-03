test="pwords"
./${test} ./gutenberg/alice.txt > ./output/${test}/alice.txt
./${test} ./gutenberg/metamorphosis.txt > ./output/${test}/metamorphosis.txt
./${test} ./gutenberg/peter.txt > ./output/${test}/peter.txt
./${test} ./gutenberg/sawyer.txt > ./output/${test}/sawyer.txt
./${test} ./gutenberg/time.txt > ./output/${test}/time.txt
./${test} ./gutenberg/alice.txt ./gutenberg/metamorphosis.txt ./gutenberg/peter.txt ./gutenberg/sawyer.txt ./gutenberg/time.txt > ./output/${test}/output.txt