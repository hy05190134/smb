package smb

import (
	"errors"
	"fmt"

	"github.com/hy05190134/smb/gss"
	"github.com/hy05190134/smb/ntlmssp"
	"github.com/hy05190134/smb/smb/encoder"
)

const ProtocolSmb = "\xFFSMB"
const ProtocolSmb2 = "\xFESMB"

const StatusOk = 0x00000000
const StatusMoreProcessingRequired = 0xc0000016
const StatusInvalidParameter = 0xc000000d
const StatusLogonFailure = 0xc000006d
const StatusUserSessionDeleted = 0xc0000203

var StatusMap = map[uint32]string{
	StatusOk:                     "OK",
	StatusMoreProcessingRequired: "More Processing Required",
	StatusInvalidParameter:       "Invalid Parameter",
	StatusLogonFailure:           "Logon failed",
	StatusUserSessionDeleted:     "User session deleted",
}

const DialectSmb_2_0_2 = 0x0202
const DialectSmb_2_1 = 0x0210
const DialectSmb_3_0 = 0x0300
const DialectSmb_3_0_2 = 0x0302
const DialectSmb_3_1_1 = 0x0311
const DialectSmb2_ALL = 0x02FF

const (
	CommandNegotiate uint16 = iota
	CommandSessionSetup
	CommandLogoff
	CommandTreeConnect
	CommandTreeDisconnect
	CommandCreate
	CommandClose
	CommandFlush
	CommandRead
	CommandWrite
	CommandLock
	CommandIOCtl
	CommandCancel
	CommandEcho
	CommandQueryDirectory
	CommandChangeNotify
	CommandQueryInfo
	CommandSetInfo
	CommandOplockBreak
)

var CommandStr = map[uint16]string{
	CommandNegotiate:      "Negotiate",
	CommandSessionSetup:   "SessionSetup",
	CommandLogoff:         "Logoff",
	CommandTreeConnect:    "TreeConnect",
	CommandTreeDisconnect: "TreeDisconnect",
	CommandCreate:         "Create",
	CommandClose:          "Close",
	CommandFlush:          "Flush",
	CommandRead:           "Read",
	CommandWrite:          "Write",
	CommandLock:           "Lock",
	CommandIOCtl:          "IOCtl",
	CommandCancel:         "Cancel",
	CommandEcho:           "Echo",
	CommandQueryDirectory: "QueryDirectory",
	CommandChangeNotify:   "ChangeNotify",
	CommandQueryInfo:      "QueryInfo",
	CommandSetInfo:        "SetInfo",
	CommandOplockBreak:    "OplockBreak",
}

const (
	_ uint16 = iota
	SecurityModeSigningEnabled
	SecurityModeSigningRequired
)

const (
	_ byte = iota
	ShareTypeDisk
	ShareTypePipe
	ShareTypePrint
)

const (
	ShareFlagManualCaching            uint32 = 0x00000000
	ShareFlagAutoCaching              uint32 = 0x00000010
	ShareFlagVDOCaching               uint32 = 0x00000020
	ShareFlagNoCaching                uint32 = 0x00000030
	ShareFlagDFS                      uint32 = 0x00000001
	ShareFlagDFSRoot                  uint32 = 0x00000002
	ShareFlagRestriceExclusiveOpens   uint32 = 0x00000100
	ShareFlagForceSharedDelete        uint32 = 0x00000200
	ShareFlagAllowNamespaceCaching    uint32 = 0x00000400
	ShareFlagAccessBasedDirectoryEnum uint32 = 0x00000800
	ShareFlagForceLevelIIOplock       uint32 = 0x00001000
	ShareFlagEnableHashV1             uint32 = 0x00002000
	ShareFlagEnableHashV2             uint32 = 0x00004000
	ShareFlagEncryptData              uint32 = 0x00008000
)

const (
	ShareCapDFS                    uint32 = 0x00000008
	ShareCapContinuousAvailability uint32 = 0x00000010
	ShareCapScaleout               uint32 = 0x00000020
	ShareCapCluster                uint32 = 0x00000040
	ShareCapAsymmetric             uint32 = 0x00000080
)

//RequestedOplockLevel
const (
	Smb2OplockLevelNone      uint8 = 0x00
	Smb2OplockLevelII        uint8 = 0x01
	Smb2OplockLevelExclusive uint8 = 0x08
	Smb2OplockLevelBatch     uint8 = 0x09
	Smb2OplockLevelLease     uint8 = 0xFF
)

//ImpersonationLeve
const (
	Anonymous uint32 = iota
	Identification
	Impersonation
	Delegate
)

//DesiredAccess
const (
	FileReadData         uint32 = 0x00000001
	FileWriteData        uint32 = 0x00000002
	FileAppendData       uint32 = 0x00000004
	FileReadEa           uint32 = 0x00000008
	FileWriteEa          uint32 = 0x00000010
	FileDeleteChild      uint32 = 0x00000040
	FileExecute          uint32 = 0x00000020
	FileReadAttributes   uint32 = 0x00000080
	FileWriteAttributes  uint32 = 0x00000100
	Delete               uint32 = 0x00010000
	ReadControl          uint32 = 0x00020000
	WriteDac             uint32 = 0x00040000
	WriteOwner           uint32 = 0x00080000
	Synchronize          uint32 = 0x00100000
	AccessSystemSecurity uint32 = 0x01000000
	MaxinumAllowed       uint32 = 0x02000000
	GenericAll           uint32 = 0x10000000
	GenericExecute       uint32 = 0x20000000
	GenericWrite         uint32 = 0x40000000
	GenericRead          uint32 = 0x80000000
)

//FileAttributes
const (
	FileAttributeArchive           uint32 = 0x00000020
	FileAttributeCompressed        uint32 = 0x00000800
	FileAttributeDirectory         uint32 = 0x00000010
	FileAttributeEncrypted         uint32 = 0x00004000
	FileAttributeHidden            uint32 = 0x00000002
	FileAttributeNormal            uint32 = 0x00000080
	FileAttributeNotContentIndexed uint32 = 0x00002000
	FileAttributeOffline           uint32 = 0x00001000
	FileAttributeReadonly          uint32 = 0x00000001
	FileAttributeReparsePoint      uint32 = 0x00000400
	FileAttributeSparseFile        uint32 = 0x00000200
	FileAttributeSystem            uint32 = 0x00000004
	FileAttributeTemporary         uint32 = 0x00000100
	FileAttributeIntegrityStream   uint32 = 0x00008000
	FileAttributeNoScrubData       uint32 = 0x00020000
)

//ShareAccess
const (
	FileShareRead   uint32 = 0x00000001
	FileShareWrite  uint32 = 0x00000002
	FileShareDelete uint32 = 0x00000003
)

//CreateDisposition
const (
	FileSupersede uint32 = iota
	FileOpen
	FileCreate
	FileOpenIf
	FileOverwrite
	FileOverwriteIf
)

//CreateOptions
const (
	FileDirectoryFile           uint32 = 0x00000001
	FileWriteThrough            uint32 = 0x00000002
	FileSequentialOnly          uint32 = 0x00000004
	FileNoIntermediateBuffering uint32 = 0x00000008
	FileSynchronousIoAlert      uint32 = 0x00000010
	FileSynchronousIoNonalert   uint32 = 0x00000020
	FileNonDirectoryFile        uint32 = 0x00000040
	FileCompleteIfOplocked      uint32 = 0x00000100
	FileNoEaKnowledge           uint32 = 0x00000200
	FileRandomAccess            uint32 = 0x00000800
	FileDeleteOnClose           uint32 = 0x00001000
	FileOpenByFileId            uint32 = 0x00002000
	FileOpenForBackupIntent     uint32 = 0x00004000
	FileNoCompression           uint32 = 0x00008000
	FileOpenRemoteInstance      uint32 = 0x00000400
	FileOpenRequireingOplock    uint32 = 0x00010000
	FileDisallowExclusive       uint32 = 0x00020000
	FileReserveOpfilter         uint32 = 0x00100000
	FileOpenReparsePoint        uint32 = 0x00200000
	FileOpenNoRecall            uint32 = 0x00400000
	FileOpenForFreeSpaceQuery   uint32 = 0x00800000
)

//Channel
const (
	Smb2ChannelNone uint32 = iota
	Smb2ChannelRdmaV1
	Smb2ChannelRdmaV1Invalidate
)

type Header struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

type NegotiateReq struct {
	Header
	StructureSize   uint16
	DialectCount    uint16 `smb:"count:Dialects"`
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGuid      []byte `smb:"fixed:16"`
	ClientStartTime uint64
	Dialects        []uint16
}

type NegotiateContext struct {
	ContentType uint16
	DataLen     uint16 `smb:"len:Data"`
	Reserved    uint32
	Data        []byte
}

//if dialects contain 0x0311, use it
type NegotiateReqExt struct {
	Header
	StructureSize          uint16
	DialectCount           uint16 `smb:"count:Dialects"`
	SecurityMode           uint16
	Reserved               uint16
	Capabilities           uint32
	ClientGuid             []byte `smb:"fixed:16"`
	NegotiateContextOffset uint16 `smb:"offset:NegotiateContextList"`
	NegotiateContextCount  uint8  `smb:"count:NegotiateContextList"`
	Reserved2              uint8
	Dialects               []uint16
	//used for 8 byte aligned
	Padding              []byte
	NegotiateContextList []NegotiateContext
}

type NegotiateRes struct {
	Header
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16
	ServerGuid           []byte `smb:"fixed:16"`
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	Reserved2            uint32
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

//logoff request&response
type LogoffReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type LogoffRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type FileID struct {
	Persistent []byte `smb:"fixed:8"`
	Volatile   []byte `smb:"fixed:8"`
}

//create file request&response
type CreateReq struct {
	Header
	StructureSize        uint16
	SecurityFlags        uint8
	RequestedOplockLevel uint8
	ImpersonationLevel   uint32
	SmbCreateFlags       uint64
	Reserved             uint64
	DesiredAccess        uint32
	FileAttributes       uint32
	ShareAccess          uint32
	CreateDisposition    uint32
	CreateOptions        uint32
	NameOffset           uint16
	NameLength           uint16
	CreateContextsOffset uint32
	CreateContextsLength uint32
	Buffer               []byte
}

type CreateRes struct {
	Header
	StructureSize        uint16
	OplockLevel          uint8
	Flags                uint8
	CreateAction         uint32
	CreationTime         uint64
	LastAccessTime       uint64
	LastWriteTime        uint64
	ChangeTime           uint64
	AllocationSize       uint64
	EndofFile            uint64
	FileAttributes       uint32
	Reserved2            uint32
	FileID               `smb:"fixed:16"`
	CreateContextsOffset uint32 `smb:"offset:Contexts"`
	CreateContextsLength uint32 `smb:"len:Contexts"`
	Contexts             []byte
}

//close file request&response
type CloseReq struct {
	Header
	StructureSize uint16
	Flags         uint16
	Reserved      uint32
	FileID        `smb:"fixed:16"`
}

type CloseRes struct {
	Header
	StructureSize  uint16
	Flags          uint16
	Reserved       uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndofFile      uint64
	FileAttributes uint32
}

//flush file request&response
type FlushReq struct {
	Header
	StructureSize uint16
	Reserved1     uint16
	Reserved2     uint32
	FileID
}

type FlushRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

//read file request&response
type ReadReq struct {
	Header
	StructureSize         uint16
	Padding               uint8
	Flags                 uint8
	Length                uint32
	Offset                uint64
	FileID                `smb:"fixed:16"`
	MinimumCount          uint32
	Channel               uint32
	RemainingBytes        uint32
	ReadChannelInfoOffset uint16 `smb:"offset:ChannelInfo"`
	ReadChannelInfoLength uint16 `smb:"len:ChannelInfo"`
	ChannelInfo           []byte
}

type ReadRes struct {
	Header
	StructureSize uint16
	DataOffset    uint8 `smb:"offset:Data"`
	Reserved      uint8
	DataLength    uint32 `smb:"len:Data"`
	DataRemaining uint32
	Reserved2     uint32
	Data          []byte
}

//write file request&response
type WriteReq struct {
	Header
	StructureSize uint16
	DataOffset    uint16
	Length        uint32
	Offset        uint64
	FileID
	Channel                uint32
	RemainingBytes         uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
	Flags                  uint32
	ChannelInfo            []byte
}

type WriteRes struct {
	Header
	StructureSize          uint16
	Reserved               uint16
	Count                  uint32
	Remaining              uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
}

//oplock break notify by server
type OplockBreakNotification struct {
	Header
	StructureSize uint16
	OplockLevel   uint8
	Reserved      uint8
	Reserved2     uint32
	FileID
}

type LeaseBreakNotification struct {
	Header
	StructureSize     uint16
	NewEpoch          uint16
	Flags             uint32
	LeaseKey          []byte `smb:"fixed:16"`
	CurrentLeaseState uint32
}

//oplock break ack by client
type OplockBreakAck struct {
	Header
	StructureSize uint16
	OplockLevel   uint8
	Reserved      uint8
	Reserved2     uint32
	FileID
}

type LeaseBreakAck struct {
	Header
	StructureSize uint16
	Reserved      uint16
	Flags         uint32
	LeaseKey      []byte `smb:"fixed:16"`
	LeaseState    uint32
	LeaseDuration uint64
}

//oplock break res by server
type OplockBreakRes struct {
	Header
	StructureSize uint16
	OplockLevel   uint8
	Reserved      uint8
	Reserved2     uint32
	FileID
}

type LeaseBreakRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
	Flags         uint32
	LeaseKey      []byte `smb:"fixed:16"`
	LeaseState    uint32
	LeaseDuration uint64
}

type LockElement struct {
	Offset   uint64
	Length   uint64
	Flags    uint32
	Reserved uint32
}

//lock request&response
type LockReq struct {
	Header
	StructureSize uint16
	LockCount     uint16 `smb:"count:Locks"`
	LockSequence  uint32 `LSN: 4bit; LockSequenceIndex: 28bit`
	FileID
	Locks []LockElement
}

type LockRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

//echo request&response
type EchoReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type EchoRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

//cancel request
type CancelReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

//ioctl request&response
type IoctlReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
	CtlCode       uint32
	FileID
	InputOffset       uint32
	InputCount        uint32
	MaxInputResponse  uint32
	OutputOffset      uint32
	OutputCount       uint32
	MaxOutputResponse uint32
	Flags             uint32
	Reserved2         uint32
	Buffer            []byte
}

type IoctlRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
	CtlCode       uint32
	FileID
	InputOffset  uint32
	InputCount   uint32
	OutputOffset uint32
	OutputCount  uint32
	Flags        uint32
	Reserved2    uint32
	Buffer       []byte
}

//query directory request&response
type QueryDirectoryReq struct {
	Header
	StructureSize        uint16
	FileInformationClass uint8
	Flags                uint8
	FileIndex            uint32
	FileID
	FileNameOffset     uint16
	FileNameLength     uint16
	OutputBufferLength uint32
	Pattern            []byte
}

type QueryDirectoryRes struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16
	OutputBufferLength uint32
	Buffer             []byte
}

//change notify request&response
type ChangeNotifyReq struct {
	Header
	StructureSize      uint16
	Flags              uint16
	OutputBufferLength uint32
	FileID
	CompletionFilter uint32
	Reserved         uint32
}

type ChangeNotifyRes struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16
	OutputBufferLength uint32
	Buffer             []byte
}

//query info request&response
type QueryInfoReq struct {
	Header
	StructureSize         uint16
	InfoType              uint8
	FileInfoClass         uint8
	OutputBufferLength    uint32
	InputBufferOffset     uint16
	Reserved              uint16
	InputBufferLength     uint32
	AdditionalInformation uint32
	Flags                 uint32
	FileID
	InputBuffer []byte
}

type QueryInfoRes struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16
	OutputBufferLength uint32
	Buffer             []byte
}

//set info request&response
type SetInfoReq struct {
	Header
	StructureSize         uint16
	InfoType              uint8
	FileInfoClass         uint8
	BufferLength          uint32
	BufferOffset          uint16
	Reserved              uint16
	AdditionalInformation uint32
	FileID
	Buffer []byte
}

type SetInfoRes struct {
	Header
	StructureSize uint16
}

type TreeConnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
	PathOffset    uint16 `smb:"offset:Path"`
	PathLength    uint16 `smb:"len:Path"`
	Path          []byte
}

type TreeConnectRes struct {
	Header
	StructureSize uint16
	ShareType     byte
	Reserved      byte
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

type TreeDisconnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeDisconnectRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  0,
		Status:        0,
		Command:       0,
		Credits:       0,
		Flags:         0,
		NextCommand:   0,
		MessageID:     0,
		Reserved:      0,
		TreeID:        0,
		SessionID:     0,
		Signature:     make([]byte, 16),
	}
}

func (s *Session) NewNegotiateReq() NegotiateReq {
	header := newHeader()
	header.Command = CommandNegotiate
	header.CreditCharge = 1
	header.MessageID = s.messageID

	dialects := []uint16{
		uint16(DialectSmb_2_1),
	}
	return NegotiateReq{
		Header:          header,
		StructureSize:   36,
		DialectCount:    uint16(len(dialects)),
		SecurityMode:    SecurityModeSigningEnabled,
		Reserved:        0,
		Capabilities:    0,
		ClientGuid:      make([]byte, 16),
		ClientStartTime: 0,
		Dialects:        dialects,
	}
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:               newHeader(),
		StructureSize:        0,
		SecurityMode:         0,
		DialectRevision:      0,
		Reserved:             0,
		ServerGuid:           make([]byte, 16),
		Capabilities:         0,
		MaxTransactSize:      0,
		MaxReadSize:          0,
		MaxWriteSize:         0,
		SystemTime:           0,
		ServerStartTime:      0,
		SecurityBufferOffset: 0,
		SecurityBufferLength: 0,
		Reserved2:            0,
		SecurityBlob:         &gss.NegTokenInit{},
	}
}

func (s *Session) NewSessionSetup1Req() (SessionSetup1Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup1Req{}, err
	}

	if s.sessionID != 0 {
		return SessionSetup1Req{}, errors.New("Bad session ID for session setup 1 message")
	}

	// Initial session setup request
	init, err := gss.NewNegTokenInit()
	if err != nil {
		return SessionSetup1Req{}, err
	}
	init.Data.MechToken = data

	return SessionSetup1Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}, nil
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

func (s *Session) NewSessionSetup2Req() (SessionSetup2Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup2Req{}, err
	}

	if s.sessionID == 0 {
		return SessionSetup2Req{}, errors.New("Bad session ID for session setup 2 message")
	}

	// Session setup request #2
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Req{}, err
	}
	resp.ResponseToken = data

	return SessionSetup2Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &resp,
	}, nil
}

func NewSessionSetup2Res() (SessionSetup2Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Res{}, err
	}
	ret := SessionSetup2Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

// NewTreeConnectReq creates a new TreeConnect message and accepts the share name
// as input.
func (s *Session) NewTreeConnectReq(name string) (TreeConnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeConnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	path := fmt.Sprintf("\\\\%s\\%s", s.options.Host, name)
	return TreeConnectReq{
		Header:        header,
		StructureSize: 9,
		Reserved:      0,
		PathOffset:    0,
		PathLength:    0,
		Path:          encoder.ToUnicode(path),
	}, nil
}

// open a new file or directory using create
func (s *Session) NewCreateReq(tree string, name string) (CreateReq, error) {
	header := newHeader()
	header.Command = CommandCreate
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = 0
	if treeId, ok := s.trees[tree]; ok {
		header.TreeID = treeId
	}

	return CreateReq{
		Header:               header,
		StructureSize:        57,
		SecurityFlags:        0,
		RequestedOplockLevel: Smb2OplockLevelBatch,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		Reserved:             0,
		DesiredAccess:        Synchronize | ReadControl | FileReadData | FileReadAttributes | FileReadEa,
		FileAttributes:       FileAttributeNormal,
		ShareAccess:          FileShareRead | FileShareWrite,
		CreateDisposition:    FileOpen,
		CreateOptions:        FileSynchronousIoNonalert | FileNonDirectoryFile,
		NameOffset:           120,
		NameLength:           uint16(len(name) * 2),
		CreateContextsOffset: 0,
		CreateContextsLength: 0,
		Buffer:               encoder.ToUnicode(name),
	}, nil
}

func (s *Session) NewReadReq(tree string) (ReadReq, error) {
	header := newHeader()
	header.Command = CommandRead
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = 0
	if treeId, ok := s.trees[tree]; ok {
		header.TreeID = treeId
	}

	return ReadReq{
		Header:                header,
		StructureSize:         49,
		Padding:               80,
		Flags:                 0,
		Length:                305, //get from create'res's end_of_file
		Offset:                0,
		FileID:                s.FileId,
		MinimumCount:          1,
		Channel:               Smb2ChannelNone,
		RemainingBytes:        0,
		ReadChannelInfoLength: 0,
		ReadChannelInfoOffset: 0,
		ChannelInfo:           []byte{0x00},
	}, nil
}

func (s *Session) NewCloseReq(tree string) (CloseReq, error) {
	header := newHeader()
	header.Command = CommandClose
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = 0
	if treeId, ok := s.trees[tree]; ok {
		header.TreeID = treeId
	}

	return CloseReq{
		Header:        header,
		StructureSize: 24,
		Flags:         1,
		Reserved:      0,
		FileID:        s.FileId,
	}, nil
}

func (s *Session) NewTreeDisconnectReq(treeId uint32) (TreeDisconnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeDisconnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = treeId

	return TreeDisconnectReq{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}

func (s *Session) NewLogoffReq() (LogoffReq, error) {
	
        header := newHeader()
	header.Command = CommandLogoff
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	return LogoffReq{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}
