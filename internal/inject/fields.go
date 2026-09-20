package inject

// 描述符与两张表的**字段混淆**（第三方报告 P1.1-5："容器/记录明文"：魔数、RVA、长度、标志）。
//
// 做法：把那些标量字段与一段由主密钥派生的掩码异或。掩码不是"加密"——
// 拿到主密钥的人当然能还原；它要挡住的是**静态可读性**：
// 反汇编/扫描产物时不再能直接看到"哪个函数被虚拟化了、它的原始 RVA 与字节码长度、哪些节被整体加密"。
//
// 关键约束：掩码必须由**主密钥 + 每构建随机的 seed**派生，而且**不能**依赖被混淆的字段本身
// （否则运行期没有起点可解）。所以每个结构用一个固定的域常量：
//
//	m_desc   = KDFEntry(master, 0xC0DE0003, FieldMaskSalt)   // 描述符 8..32
//	m_image  = KDFEntry(master, 0xC0DE0004, FieldMaskSalt)   // 解密表：表头 12..24、每条 0..12
//	m_verify = KDFEntry(master, 0xC0DE0005, FieldMaskSalt)   // 校验表：每条 0..24
//
// C 侧对应 stub/win/x64/vm_kdf.c 的 vm_field_mask()，两侧由 KAT 钉死。
const (
	FieldMaskDomainDesc   = uint32(0xC0DE0003)
	FieldMaskDomainImage  = uint32(0xC0DE0004)
	FieldMaskDomainVerify = uint32(0xC0DE0005)
)

// FieldMask 派生某个域下的 32 字节掩码。
func FieldMask(master []byte, domain, fieldMaskSalt uint32) [32]byte {
	return KDFEntry(master, domain, fieldMaskSalt)
}

// XorMask 就地把 buf[off:off+n] 与 mask 逐字节异或。异或是对合的：
// 打包端"加掩码"和运行期"去掩码"是同一个调用。mask 允许是 32 字节掩码的**切片**
// （同一个域里表头和条目各用一段，避免不同结构共用同一段密钥流）。
func XorMask(buf []byte, off, n int, mask []byte) {
	if n > len(mask) {
		n = len(mask)
	}
	for i := 0; i < n; i++ {
		buf[off+i] ^= mask[i]
	}
}
