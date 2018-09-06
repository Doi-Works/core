FROM doichain/docker:core-base
ARG DOICHAIN_VER=master
ENV DOICHAIN_VER $DOICHAIN_VER

#Setup run vars
ENV CONFIRM_ADDRESS ""
ENV CONNECTION_NODE 5.9.154.226
ENV DAPP_URL http://localhost:3000
ENV NODE_PORT 8338
ENV NODE_PORT_TESTNET 18338
ENV NODE_PORT_REGTEST 18445
ENV REGTEST false
ENV TESTNET false
ENV RPC_ALLOW_IP 127.0.0.1
ENV RPC_PASSWORD ""
ENV RPC_PORT 8339
ENV RPC_PORT_TESTNET 18339
ENV RPC_PORT_REGTEST 18332
ENV RPC_USER admin

#Install doichain-core
WORKDIR /home/doichain
RUN mkdir .doichain && \
	sudo git clone --branch ${DOICHAIN_VER} --depth 1 https://github.com/Doichain/core.git doichain-core && \
	cd doichain-core && \
	sudo ./autogen.sh && \
	sudo ./configure --without-gui  --disable-tests  --disable-gui-tests CXXFLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768" && \
	sudo make && \
	sudo make install

#Copy start scripts
WORKDIR /home/doichain/doichain-core
COPY contrib/docker/entrypoint.sh entrypoint.sh
COPY contrib/docker/getblocktimes.sh getblocktimes.sh
COPY contrib/docker/doichain-start.sh doichain-start.sh

RUN sudo dos2unix \
	entrypoint.sh \
	doichain-start.sh && \
	sudo chmod +x \
	entrypoint.sh \
	doichain-start.sh \
	getblocktimes.sh && \
	sudo apt-get purge -y dos2unix && \
	sudo rm -rf /var/lib/apt/lists/*

#Create data dir
WORKDIR /home/doichain
RUN mkdir data && \
	cd data && \
	mkdir doichain &&\
	sudo rm -rf /home/doichain/.doichain && \
	sudo ln -s /home/doichain/data/doichain /home/doichain/.doichain

#Run entrypoint
WORKDIR /home/doichain
ENTRYPOINT ["/home/doichain/doichain-core/entrypoint.sh"]

CMD ["/home/doichain/doichain-core/doichain-start.sh"]

#Expose ports
EXPOSE $NODE_PORT $RPC_PORT_REGTEST
