package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/common/systemcontract"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/mux"
	"io/fs"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"strings"
	"unicode"
	"unsafe"

	_ "github.com/ethereum/go-ethereum/eth/tracers/native"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

type artifactData struct {
	Bytecode         string `json:"bytecode"`
	DeployedBytecode string `json:"deployedBytecode"`
}

type dummyChainContext struct {
}

func (d *dummyChainContext) Engine() consensus.Engine {
	return nil
}

func (d *dummyChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func createFastFinalityExtraData(config genesisConfig) []byte {
	if len(config.Validators) != len(config.VotingKeys) {
		log.Panicf("ecdsa and bls keys doesn't match (%d != %d)", len(config.Validators), len(config.VotingKeys))
	}
	extra := make([]byte, 32)
	extra = append(extra, byte(len(config.Validators)))
	for i, v := range config.Validators {
		extra = append(extra, v.Bytes()...)
		if len(config.VotingKeys[i]) != 48 {
			log.Panicf("bls key has incorrect length, must be 48, instead of %d", len(config.VotingKeys[i]))
		}
		extra = append(extra, config.VotingKeys[i]...)
	}
	extra = append(extra, bytes.Repeat([]byte{0}, 65)...)
	return extra
}

func createExtraData(config genesisConfig) []byte {
	if config.SupportedForks.FastFinalityBlock != nil && (*big.Int)(config.SupportedForks.FastFinalityBlock).Uint64() == 0 {
		return createFastFinalityExtraData(config)
	}
	validators := config.Validators
	extra := make([]byte, 32+20*len(validators)+65)
	for i, v := range validators {
		copy(extra[32+20*i:], v.Bytes())
	}
	return extra
}

func readStateObjectsFromState(f *state.StateDB) map[common.Address]*state.StateObject {
	var result map[common.Address]*state.StateObject
	rs := reflect.ValueOf(*f)
	rf := rs.FieldByName("stateObjects")
	rs2 := reflect.New(rs.Type()).Elem()
	rs2.Set(rs)
	rf = rs2.FieldByName("stateObjects")
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	ri := reflect.ValueOf(&result).Elem()
	ri.Set(rf)
	return result
}

func readDirtyStorageFromState(f *state.StateObject) state.Storage {
	var result map[common.Hash]common.Hash
	rs := reflect.ValueOf(*f)
	rf := rs.FieldByName("dirtyStorage")
	rs2 := reflect.New(rs.Type()).Elem()
	rs2.Set(rs)
	rf = rs2.FieldByName("dirtyStorage")
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	ri := reflect.ValueOf(&result).Elem()
	ri.Set(rf)
	return result
}

var stakingAddress = common.HexToAddress("0x0000000000000000000000000000000000001000")
var slashingIndicatorAddress = common.HexToAddress("0x0000000000000000000000000000000000001001")
var systemRewardAddress = common.HexToAddress("0x0000000000000000000000000000000000001002")
var stakingPoolAddress = common.HexToAddress("0x0000000000000000000000000000000000007001")
var governanceAddress = common.HexToAddress("0x0000000000000000000000000000000000007002")
var chainConfigAddress = common.HexToAddress("0x0000000000000000000000000000000000007003")
var runtimeUpgradeAddress = common.HexToAddress("0x0000000000000000000000000000000000007004")
var deployerProxyAddress = common.HexToAddress("0x0000000000000000000000000000000000007005")
var intermediarySystemAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")
var tokenManagerContract = common.HexToAddress("0x0000000000000000000000000000000000001008")
var crossChainContract = common.HexToAddress("0x0000000000000000000000000000000000002000")

//go:embed build/contracts/RuntimeProxy.json
var runtimeProxyArtifact []byte

//go:embed build/contracts/Staking.json
var stakingRawArtifact []byte

//go:embed build/contracts/StakingPool.json
var stakingPoolRawArtifact []byte

//go:embed build/contracts/StakingConfig.json
var stakingConfigRawArtifact []byte

//go:embed build/contracts/SlashingIndicator.json
var slashingIndicatorRawArtifact []byte

//go:embed build/contracts/SystemReward.json
var systemRewardRawArtifact []byte

//go:embed build/contracts/Governance.json
var governanceRawArtifact []byte

//go:embed build/contracts/RuntimeUpgrade.json
var runtimeUpgradeRawArtifact []byte

//go:embed build/contracts/DeployerProxy.json
var deployerProxyRawArtifact []byte

func newArguments(typeNames ...string) abi.Arguments {
	var args abi.Arguments
	for i, tn := range typeNames {
		abiType, err := abi.NewType(tn, tn, nil)
		if err != nil {
			panic(err)
		}
		args = append(args, abi.Argument{Name: fmt.Sprintf("%d", i), Type: abiType})
	}
	return args
}

type consensusParams struct {
	ActiveValidatorsLength   uint32                `json:"activeValidatorsLength"`
	CandidateLength          uint32                `json:"candidateLength"`
	EpochBlockInterval       uint32                `json:"epochBlockInterval"`
	MisdemeanorThreshold     uint32                `json:"misdemeanorThreshold"`
	FelonyThreshold          uint32                `json:"felonyThreshold"`
	ValidatorJailEpochLength uint32                `json:"validatorJailEpochLength"`
	UndelegatePeriod         uint32                `json:"undelegatePeriod"`
	MinValidatorStakeAmount  *math.HexOrDecimal256 `json:"minValidatorStakeAmount"`
	MinStakingAmount         *math.HexOrDecimal256 `json:"minStakingAmount"`
	MaxDelegateTotalAmount   *math.HexOrDecimal256 `json:"maxDelegateTotalAmount"`
	FinalityRewardRatio      uint16                `json:"finalityRewardRatio"`
}

type supportedForks struct {
	VerifyParliaBlock *math.HexOrDecimal256 `json:"verifyParliaBlock"`
	BlockRewardsBlock *math.HexOrDecimal256 `json:"blockRewardsBlock"`
	FastFinalityBlock *math.HexOrDecimal256 `json:"fastFinalityBlock"`
}

type genesisConfig struct {
	ChainId         int64                     `json:"chainId"`
	SupportedForks  supportedForks            `json:"supportedForks"`
	Deployers       []common.Address          `json:"deployers"`
	Validators      []common.Address          `json:"validators"`
	VotingKeys      []hexutil.Bytes           `json:"votingKeys"`
	Owners          []common.Address          `json:"owners"`
	SystemTreasury  map[common.Address]uint16 `json:"systemTreasury"`
	ConsensusParams consensusParams           `json:"consensusParams"`
	VotingPeriod    int64                     `json:"votingPeriod"`
	Faucet          map[common.Address]string `json:"faucet"`
	CommissionRate  int64                     `json:"commissionRate"`
	InitialStakes   map[common.Address]string `json:"initialStakes"`
	BlockRewards    *math.HexOrDecimal256     `json:"blockRewards"`
}

func hexBytesToNormalBytes(value []hexutil.Bytes) (result [][]byte) {
	for _, v := range value {
		result = append(result, v)
	}
	return result
}

func traceCallError(deployedBytecode []byte) {
	for _, c := range deployedBytecode[64:] {
		if c >= 32 && c <= unicode.MaxASCII {
			print(string(c))
		}
	}
	println()
}

func byteCodeFromArtifact(rawArtifact []byte) []byte {
	artifact := &artifactData{}
	if err := json.Unmarshal(rawArtifact, artifact); err != nil {
		panic(err)
	}
	return hexutil.MustDecode(artifact.Bytecode)
}

func mustNewType(t string) abi.Type {
	typ, _ := abi.NewType(t, t, nil)
	return typ
}

func createInitializer(typeNames []string, params []interface{}) []byte {
	initializerArgs, err := newArguments(typeNames...).Pack(params...)
	if err != nil {
		panic(err)
	}
	initializerSig := crypto.Keccak256([]byte(fmt.Sprintf("initialize(%s)", strings.Join(typeNames, ","))))[:4]
	return append(initializerSig, initializerArgs...)
}

func createSimpleBytecode(rawArtifact []byte) []byte {
	constructorArgs, err := newArguments(
		"address", "address", "address", "address", "address", "address", "address", "address").Pack(
		stakingAddress, slashingIndicatorAddress, systemRewardAddress, stakingPoolAddress, governanceAddress, chainConfigAddress, runtimeUpgradeAddress, deployerProxyAddress)
	if err != nil {
		panic(err)
	}
	return append(byteCodeFromArtifact(rawArtifact), constructorArgs...)
}

func createProxyBytecodeWithConstructor(rawArtifact []byte, initTypes []string, initArgs []interface{}) []byte {
	constructorArgs, err := newArguments(
		"address", "address", "address", "address", "address", "address", "address", "address").Pack(
		stakingAddress, slashingIndicatorAddress, systemRewardAddress, stakingPoolAddress, governanceAddress, chainConfigAddress, runtimeUpgradeAddress, deployerProxyAddress)
	if err != nil {
		panic(err)
	}
	proxyArgs := abi.Arguments{
		abi.Argument{Type: mustNewType("address")},
		abi.Argument{Type: mustNewType("bytes")},
		abi.Argument{Type: mustNewType("bytes")},
	}
	runtimeProxyConstructor, err := proxyArgs.Pack(
		// address of runtime upgrade that can do future upgrades
		runtimeUpgradeAddress,
		// bytecode of the default implementation system smart contract
		append(byteCodeFromArtifact(rawArtifact), constructorArgs...),
		// initializer for system smart contract (it's called using "init()" function)
		createInitializer(initTypes, initArgs),
	)
	if err != nil {
		panic(err)
	}
	return append(byteCodeFromArtifact(runtimeProxyArtifact), runtimeProxyConstructor...)
}

func createVirtualMachine(genesis *core.Genesis, systemContract common.Address, balance *big.Int) (*state.StateDB, *vm.EVM) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabaseWithConfig(rawdb.NewDatabase(memorydb.New()), &trie.Config{}), nil)
	if balance != nil {
		statedb.SetBalance(systemContract, balance)
	}
	block := genesis.ToBlock(nil)
	blockContext := core.NewEVMBlockContext(block.Header(), &dummyChainContext{}, &common.Address{})
	txContext := core.NewEVMTxContext(
		types.NewMessage(common.Address{}, &systemContract, 0, big.NewInt(0), 10_000_000, big.NewInt(0), []byte{}, nil, false),
	)
	chainConfig := *genesis.Config
	// make copy of chain config with disabled EIP-158 (for testing period)
	//chainConfig.EIP158Block = nil
	return statedb, vm.NewEVM(blockContext, txContext, statedb, &chainConfig, vm.Config{})
}

func invokeConstructorOrPanic(genesis *core.Genesis, systemContract common.Address, rawArtifact []byte, typeNames []string, params []interface{}, balance *big.Int) {
	if balance == nil {
		balance = big.NewInt(0)
	}
	statedb, virtualMachine := createVirtualMachine(genesis, systemContract, balance)
	var bytecode []byte
	if systemContract == runtimeUpgradeAddress {
		bytecode = createSimpleBytecode(rawArtifact)
	} else {
		bytecode = createProxyBytecodeWithConstructor(rawArtifact, typeNames, params)
	}
	result, _, err := virtualMachine.CreateWithAddress(common.Address{}, bytecode, 100_000_000, big.NewInt(0), systemContract)
	if err != nil {
		traceCallError(result)
		panic(err)
	}
	if genesis.Alloc == nil {
		genesis.Alloc = make(core.GenesisAlloc)
	}
	// constructor might have side effects so better to save all state changes
	stateObjects := readStateObjectsFromState(statedb)
	for addr, stateObject := range stateObjects {
		storage := readDirtyStorageFromState(stateObject)
		genesisAccount := core.GenesisAccount{
			Code:    stateObject.Code(statedb.Database()),
			Storage: storage.Copy(),
			Balance: stateObject.Balance(),
		}
		genesis.Alloc[addr] = genesisAccount
	}
	if systemContract == stakingAddress {
		res, _, err := virtualMachine.Call(vm.AccountRef(common.Address{}), stakingAddress, hexutil.MustDecode("0xfacd743b0000000000000000000000000000000000000000000000000000000000000000"), 10_000_000, big.NewInt(0))
		if err != nil {
			traceCallError(result)
			panic(err)
		}
		println(hexutil.Encode(res))
		res, _, err = virtualMachine.Call(vm.AccountRef(common.Address{}), stakingAddress, hexutil.MustDecode("0xd951e18600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), 10_000_000, big.NewInt(0))
		if err != nil {
			traceCallError(result)
			panic(err)
		}
		println(hexutil.Encode(res))
	}
	// someone touches zero address and it increases nonce
	delete(genesis.Alloc, common.Address{})
}

func createGenesisConfig(config genesisConfig, targetFile string) ([]byte, error) {
	genesis := defaultGenesisConfig(config)
	if len(config.Owners) == 0 {
		config.Owners = config.Validators
	}
	// extra data
	genesis.ExtraData = createExtraData(config)
	genesis.Config.Parlia.Epoch = uint64(config.ConsensusParams.EpochBlockInterval)
	// execute system contracts
	var initialStakes []*big.Int
	initialStakeTotal := big.NewInt(0)
	for _, v := range config.Validators {
		rawInitialStake, ok := config.InitialStakes[v]
		if !ok {
			return nil, fmt.Errorf("initial stake is not found for validator: %s", v.Hex())
		}
		initialStake, err := hexutil.DecodeBig(rawInitialStake)
		if err != nil {
			return nil, err
		}
		initialStakes = append(initialStakes, initialStake)
		initialStakeTotal.Add(initialStakeTotal, initialStake)
	}
	invokeConstructorOrPanic(genesis, stakingAddress, stakingRawArtifact, []string{"address[]", "bytes[]", "address[]", "uint256[]", "uint16"}, []interface{}{
		config.Validators,
		hexBytesToNormalBytes(config.VotingKeys),
		config.Owners,
		initialStakes,
		uint16(config.CommissionRate),
	}, initialStakeTotal)
	invokeConstructorOrPanic(genesis, chainConfigAddress, stakingConfigRawArtifact, []string{"uint32", "uint32", "uint32", "uint32", "uint32", "uint32", "uint32", "uint256", "uint256", "uint256", "uint16"}, []interface{}{
		config.ConsensusParams.ActiveValidatorsLength,
		config.ConsensusParams.CandidateLength,
		config.ConsensusParams.EpochBlockInterval,
		config.ConsensusParams.MisdemeanorThreshold,
		config.ConsensusParams.FelonyThreshold,
		config.ConsensusParams.ValidatorJailEpochLength,
		config.ConsensusParams.UndelegatePeriod,
		(*big.Int)(config.ConsensusParams.MinValidatorStakeAmount),
		(*big.Int)(config.ConsensusParams.MinStakingAmount),
		(*big.Int)(config.ConsensusParams.MaxDelegateTotalAmount),
		config.ConsensusParams.FinalityRewardRatio,
	}, nil)
	invokeConstructorOrPanic(genesis, slashingIndicatorAddress, slashingIndicatorRawArtifact, []string{}, []interface{}{}, nil)
	invokeConstructorOrPanic(genesis, stakingPoolAddress, stakingPoolRawArtifact, []string{}, []interface{}{}, nil)
	var treasuryAddresses []common.Address
	var treasuryShares []uint16
	for k, v := range config.SystemTreasury {
		treasuryAddresses = append(treasuryAddresses, k)
		treasuryShares = append(treasuryShares, v)
	}
	invokeConstructorOrPanic(genesis, systemRewardAddress, systemRewardRawArtifact, []string{"address[]", "uint16[]"}, []interface{}{
		treasuryAddresses, treasuryShares,
	}, nil)
	invokeConstructorOrPanic(genesis, governanceAddress, governanceRawArtifact, []string{"uint256", "string"}, []interface{}{
		big.NewInt(config.VotingPeriod), "BPC Governance",
	}, nil)
	invokeConstructorOrPanic(genesis, runtimeUpgradeAddress, runtimeUpgradeRawArtifact, []string{"address"}, []interface{}{
		systemcontract.EvmHookRuntimeUpgradeAddress,
	}, nil)
	invokeConstructorOrPanic(genesis, deployerProxyAddress, deployerProxyRawArtifact, []string{"address[]"}, []interface{}{
		config.Deployers,
	}, nil)
	// create system contract
	genesis.Alloc[intermediarySystemAddress] = core.GenesisAccount{
		Balance: big.NewInt(0),
	}
	// apply faucet
	for key, value := range config.Faucet {
		balance, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			return nil, fmt.Errorf("failed to parse number (%s)", value)
		}
		genesis.Alloc[key] = core.GenesisAccount{
			Balance: balance,
		}
	}
	// save to file
	newJson, _ := json.MarshalIndent(genesis, "", "  ")
	if targetFile == "stdout" {
		_, err := os.Stdout.Write(newJson)
		return newJson, err
	} else if targetFile == "stderr" {
		_, err := os.Stderr.Write(newJson)
		return newJson, err
	}
	return newJson, ioutil.WriteFile(targetFile, newJson, fs.ModePerm)
}

func decimalToBigInt(value *math.HexOrDecimal256) *big.Int {
	if value == nil {
		return nil
	}
	return (*big.Int)(value)
}

func defaultGenesisConfig(config genesisConfig) *core.Genesis {
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(config.ChainId),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		RamanujanBlock:      big.NewInt(0),
		NielsBlock:          big.NewInt(0),
		MirrorSyncBlock:     big.NewInt(0),
		BrunoBlock:          big.NewInt(0),

		// supported forks
		VerifyParliaBlock: decimalToBigInt(config.SupportedForks.VerifyParliaBlock),
		BlockRewardsBlock: decimalToBigInt(config.SupportedForks.BlockRewardsBlock),
		FastFinalityBlock: decimalToBigInt(config.SupportedForks.FastFinalityBlock),

		Parlia: &params.ParliaConfig{
			Period: 3,
			// epoch length is managed by consensus params
			BlockRewards: decimalToBigInt(config.BlockRewards),
		},
	}
	return &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  0x5e9da7ce,
		ExtraData:  nil,
		GasLimit:   0x2625a00,
		Difficulty: big.NewInt(0x01),
		Mixhash:    common.Hash{},
		Coinbase:   common.Address{},
		Alloc:      nil,
		Number:     0x00,
		GasUsed:    0x00,
		ParentHash: common.Hash{},
	}
}

var allSupportedForks = supportedForks{
	VerifyParliaBlock: math.NewHexOrDecimal256(0),
	BlockRewardsBlock: math.NewHexOrDecimal256(0),
	FastFinalityBlock: math.NewHexOrDecimal256(0),
}

var localNetConfig = genesisConfig{
	ChainId:        1337,
	SupportedForks: allSupportedForks,
	// who is able to deploy smart contract from genesis block
	Deployers: []common.Address{
		common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"),
	},
	// list of default validators
	Validators: []common.Address{
		common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"),
	},
	VotingKeys: []hexutil.Bytes{
		hexutil.MustDecode("0x8b09f47df1cdb2d2a90b213726c46412059425a7034b3f0f22f611b8748113893a77220cbdf520057785512062a83541"),
	},
	SystemTreasury: map[common.Address]uint16{
		common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"): 10000,
	},
	ConsensusParams: consensusParams{
		ActiveValidatorsLength:   1,
		EpochBlockInterval:       100,
		MisdemeanorThreshold:     10,
		FelonyThreshold:          100,
		ValidatorJailEpochLength: 1,
		UndelegatePeriod:         0,
		MinValidatorStakeAmount:  (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0xde0b6b3a7640000")), // 1 ether
		MinStakingAmount:         (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0xde0b6b3a7640000")), // 1 ether
	},
	InitialStakes: map[common.Address]string{
		common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"): "0x3635c9adc5dea00000", // 1000 eth
	},
	// owner of the governance
	VotingPeriod: 20, // 1 minute
	// faucet
	Faucet: map[common.Address]string{
		common.HexToAddress("0x00a601f45688dba8a070722073b015277cf36725"): "0x21e19e0c9bab2400000",
		common.HexToAddress("0x57BA24bE2cF17400f37dB3566e839bfA6A2d018a"): "0x21e19e0c9bab2400000",
		common.HexToAddress("0xEbCf9D06cf9333706E61213F17A795B2F7c55F1b"): "0x21e19e0c9bab2400000",
	},
}

var devNetConfig = genesisConfig{
	ChainId:        16002,
	SupportedForks: allSupportedForks,
	// who is able to deploy smart contract from genesis block (it won't generate event log)
	Deployers: []common.Address{},
	// list of default validators (it won't generate event log)
	Validators: []common.Address{
		common.HexToAddress("0x73a8bceFA940Cefbf4cADB9fa79c30Ac283BA867"),
		common.HexToAddress("0x345D31A29dE1f8388EA7954f0dDF73782a9caD08"),
		common.HexToAddress("0x378E1761be54ab6545e6563d1b59b424D3eE31A5"),
		common.HexToAddress("0x000E0883978b34302EF7359cB480299767EE36a2"),
		common.HexToAddress("0xC359Fe96EfD30F289608804DDDFd46EB14162430"),
		common.HexToAddress("0x930B166e73B4B5f93299D3E4739F9a1dc92a8407"),
		common.HexToAddress("0x1Edb50507114Cfb3D082d55fDfA6FDcFF4EDa591"),
		common.HexToAddress("0xB38eA6371499c1B364C61bF15404760374962339"),
		common.HexToAddress("0xF016A30Aeb1AaFa2EB4b2deBf981a153246C9507"),
		common.HexToAddress("0x69C1E8b33254BEaf4BBc35EA49206b24172341bE"),
		common.HexToAddress("0xa8fd80cA9D309a7dd34785975cF03de1F9D85C5B"),
		common.HexToAddress("0x3D97A28C98B5fb50B4FaeC70F98597513929C0a6"),
		common.HexToAddress("0xe1b34f145262c06e74a58c111CDbC148753BBcC1"),
	},
	VotingKeys: []hexutil.Bytes{
		hexutil.MustDecode("0x808e4b613742a68f3983f635f5f2ac9222c111003150405a64590046fcd7f4cca5f74f3044d5bf078f2e0cba13e097e6"),
		hexutil.MustDecode("0x87b37fe1532441d263f711104747acd1774a54685d6180cd247d2313389a412c4231cb74088b7e11b874294d827f9a11"),
		hexutil.MustDecode("0xb6095a681bb0dc0f30d5901159e7cc69eb3d1ee4854f0a78675b2b98ad033acb2c1bb3eceb0a5db358ed7f819808e4c0"),
		hexutil.MustDecode("0x98ba1a92c22e2d0f8d3c3a0a04cac7697206c86bc3c53bead6e6e93831f53481c198ae269a1e0caa03c135e325af8e52"),
		hexutil.MustDecode("0xaba2c1fd0c5cc197ae46191f864fa5a9bfbfd601c9b3cf5c73959b328748ac5dc679f0c52cd84623412e37a19a70ecbc"),
		hexutil.MustDecode("0x89af11d4233b236b4422afd50123c1a6bb1ec17d08b1eed77910fa049190fd90dee9aa199b4c3ce142f4bd0c0d3f1f33"),
		hexutil.MustDecode("0xb69b7c2747253ed430108172eeeedb63a7d4f708a6cbca3db8baf51129e1c1c02c1e48bcc6dceffa1ff544316c119628"),
		hexutil.MustDecode("0x8bdeadb64716de8dd6dd9e29ddb15d0522d8dae1c28b127b29711c6682f9b4e8560281b6db0f57eac86b55e79764b489"),
		hexutil.MustDecode("0x91ad167014f642ae0a366765a6501b156c38888d1e0d867259c6aeac0cf904c4c6a06544eb5b74f55bb1eb453b2a5d46"),
		hexutil.MustDecode("0x8e732b5888a1121ef3d9b89d80b41cade0a43fc5cf1648ec05097c0d8eb4bbf83431859fc1ad41955814ca3a0e38829f"),
		hexutil.MustDecode("0x8e783e1683620221357e297b2a3e71692e7ffa2cf4a1a906980b9104186bf583894be91a847a06b9c65aaba0d979d705"),
		hexutil.MustDecode("0x93dc4022e521f6ba404b17f2c9976d845b2a32b2274e800a62e265f17aad4dac40da648d5e2c3196639baeab25bac6a7"),
		hexutil.MustDecode("0xb1a04391a1049776a4681f5995a9d669d9d708cde2868a379476f18405195a72b01716af2ee3d4d4840aed1be02adcd5"),
	},
	SystemTreasury: map[common.Address]uint16{
		common.HexToAddress("0xA39109D3326e9Eb09cf04D43f8f65FBC82A610b2"): 10000,
	},
	ConsensusParams: consensusParams{
		ActiveValidatorsLength:   17,                                                                         // suggested values are (3k+1, where k is honest validators, even better): 7, 13, 19, 25, 31...
		CandidateLength:          31,                                                                         // suggested values are (3k+1, where k is honest validators, even better): 7, 13, 19, 25, 31...
		EpochBlockInterval:       100,                                                                        // better to use 1 day epoch (86400/3=28800, where 3s is block time)
		MisdemeanorThreshold:     3,                                                                          // after missing this amount of blocks per day validator losses all daily rewards (penalty)
		FelonyThreshold:          5,                                                                          // after missing this amount of blocks per day validator goes in jail for N epochs
		ValidatorJailEpochLength: 2,                                                                          // how many epochs validator should stay in jail (7 epochs = ~7 days)
		UndelegatePeriod:         3,                                                                          // allow claiming funds only after 6 epochs (~7 days)
		MinValidatorStakeAmount:  (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x3635c9adc5dea00000")),     // how many tokens validator must stake to create a validator (in ether)
		MinStakingAmount:         (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x56bc75e2d63100000")),      // minimum staking amount for delegators (in ether)
		MaxDelegateTotalAmount:   (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x108b2a2c28029100000000")), // minimum staking amount for delegators (in ether)
		FinalityRewardRatio:      16,
	},
	InitialStakes: map[common.Address]string{
		common.HexToAddress("0x73a8bceFA940Cefbf4cADB9fa79c30Ac283BA867"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x345D31A29dE1f8388EA7954f0dDF73782a9caD08"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x378E1761be54ab6545e6563d1b59b424D3eE31A5"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x000E0883978b34302EF7359cB480299767EE36a2"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0xC359Fe96EfD30F289608804DDDFd46EB14162430"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x930B166e73B4B5f93299D3E4739F9a1dc92a8407"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x1Edb50507114Cfb3D082d55fDfA6FDcFF4EDa591"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0xB38eA6371499c1B364C61bF15404760374962339"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0xF016A30Aeb1AaFa2EB4b2deBf981a153246C9507"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x69C1E8b33254BEaf4BBc35EA49206b24172341bE"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0xa8fd80cA9D309a7dd34785975cF03de1F9D85C5B"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0x3D97A28C98B5fb50B4FaeC70F98597513929C0a6"): "0xee3a5f48a68b580000000",
		common.HexToAddress("0xe1b34f145262c06e74a58c111CDbC148753BBcC1"): "0xee3a5f48a68b580000000",
	},
	// owner of the governance
	VotingPeriod: 60, // 3 minutes
	BlockRewards: (*math.HexOrDecimal256)(hexutil.MustDecodeBig("0x1cbc5677840b10000")),
	// faucet
	Faucet: map[common.Address]string{
		common.HexToAddress("0x21748156443D5E4305ED0ff96439e410fB9f596A"): "0x19d971e4fe8401000000000", // governance
		common.HexToAddress("0x6b52FAd1C487316906c55f5C6FD2A575108c6E41"): "0x39e7139a8c08fa000000000", // faucet (10kk)
		common.HexToAddress("0x2C7C5dA55471450a9CB71Bd0A9bd2e49399A77Ee"): "0x33b2e3c9fd0804000000000", // governance
		common.HexToAddress("0xdBdd7B97F4EfA1aCF94D1e7EEC256fA8B6755D06"): "0x2327b99dd50572000000000", // faucet (10kk)
		common.HexToAddress("0x80020118c34681440681E2648fA29Ab08089936d"): "0x24306c4097859c000000000", // governance
		common.HexToAddress("0xeb17BA9F179e2649098e538E9c729F55d3365671"): "0x813f3978f89408000000000", // faucet (10kk)
	},
}

func returnError(writer http.ResponseWriter, err error) {
	writer.WriteHeader(500)
	_, _ = writer.Write([]byte(err.Error()))
}

func handleCorsRequest(w http.ResponseWriter, r *http.Request) bool {
	var origin string
	if origin = r.Header.Get("Origin"); origin == "" {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	if r.Method != "OPTIONS" || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	headers := []string{"Content-Type", "Accept"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	return true
}

func httpRpcServer() {
	r := mux.NewRouter()
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				returnError(writer, err.(error))
				return
			}
		}()
		if handleCorsRequest(writer, request) {
			return
		}
		input, err := ioutil.ReadAll(request.Body)
		if err != nil {
			returnError(writer, err)
			return
		}
		genesis := &genesisConfig{}
		err = json.Unmarshal(input, genesis)
		if err != nil {
			returnError(writer, err)
			return
		}
		result, err := createGenesisConfig(*genesis, "stdout")
		if err != nil {
			returnError(writer, err)
			return
		}
		_, _ = writer.Write(result)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(200)
	})
	if err := http.ListenAndServe(":8080", r); err != nil {
		panic(err)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--http" {
		httpRpcServer()
		return
	}
	if len(args) > 0 {
		fileContents, err := os.ReadFile(args[0])
		if err != nil {
			panic(err)
		}
		genesis := &genesisConfig{}
		err = json.Unmarshal(fileContents, genesis)
		if err != nil {
			panic(err)
		}
		outputFile := "stdout"
		if len(args) > 1 {
			outputFile = args[1]
		}
		_, err = createGenesisConfig(*genesis, outputFile)
		if err != nil {
			panic(err)
		}
		return
	}
	//fmt.Printf("building local net\n")
	//if _, err := createGenesisConfig(localNetConfig, "localnet.json"); err != nil {
	//	panic(err)
	//}
	fmt.Printf("\nbuilding dev net\n")
	if _, err := createGenesisConfig(devNetConfig, "devnet.json"); err != nil {
		panic(err)
	}
	fmt.Printf("\n")
}
