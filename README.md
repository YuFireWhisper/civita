Civita 是專為移動裝置設計的極端去中心化區塊鏈，旨在建立輕量級、高效的去中心化框架。

## 特性
- **VDF (Verifiable Delay Function)**: Civita 利用 VDF 取代基於哈希的工作量證明 (Proof of Work, PoW) 機制，在確保安全性的同時，大幅降低算力需求。
- **UTXO (Unspent Transaction Output)**: 採用 UTXO 降低每個狀態轉換的耦合程度，提升交易處理效率。
- **MMR (Merkle Mountain Range)**: 使用 MMR 儲存狀態，讓每個節點只需儲存與自己相關的數據，並且只需少量數據即可更新與驗證區塊鏈狀態。
- **GHOST (Greedy Heaviest Observed Subtree)**: 採用 GHOST 區塊選擇規則，提高區塊鏈的吞吐量和安全性。
- **動態鏈配置**: Civita 支持動態配置鏈參數，而不需要硬分岔，提升網絡的靈活性和適應性。
- **低記憶體佔用**: 通過 RocksDB 作為底層數據庫，Civita 可以將鍵值對存儲在磁碟中，顯著降低記憶體佔用。
