#!/bin/bash

# ============================================================
# 基础配置（仅路径和密钥长度，不涉及证书字段和有效期）
# ============================================================
BASE_DIR="$(cd "$(dirname "$0")" && pwd)/roots"   # 存放所有 CA 的根目录
KEY_LEN=2048                                      # RSA 密钥长度
# ============================================================

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if ! command -v openssl &> /dev/null; then
    echo -e "${RED}错误：未找到 openssl，请安装。${NC}"
    exit 1
fi

mkdir -p "$BASE_DIR"

# ------------------------------------------------------------
# 交互式获取证书主题（无默认值，强制输入）
# 用法：get_subj [CN提示名]  返回全局变量 SUBJ_STRING
# ------------------------------------------------------------
get_subj() {
    local cn_hint="$1"
    local country state city org ou cn

    echo -e "${YELLOW}请完整输入以下证书字段（不能为空）${NC}"

    while [ -z "$country" ]; do
        read -p "国家 (C): " country
        [ -z "$country" ] && echo -e "${RED}国家不能为空，请重新输入。${NC}"
    done

    while [ -z "$state" ]; do
        read -p "省份 (ST): " state
        [ -z "$state" ] && echo -e "${RED}省份不能为空，请重新输入。${NC}"
    done

    while [ -z "$city" ]; do
        read -p "城市 (L): " city
        [ -z "$city" ] && echo -e "${RED}城市不能为空，请重新输入。${NC}"
    done

    while [ -z "$org" ]; do
        read -p "组织 (O): " org
        [ -z "$org" ] && echo -e "${RED}组织不能为空，请重新输入。${NC}"
    done

    while [ -z "$ou" ]; do
        read -p "部门 (OU): " ou
        [ -z "$ou" ] && echo -e "${RED}部门不能为空，请重新输入。${NC}"
    done

    while [ -z "$cn" ]; do
        read -p "通用名 (CN) [${cn_hint}]: " cn
        [ -z "$cn" ] && echo -e "${RED}通用名不能为空，请重新输入。${NC}"
    done

    SUBJ_STRING="/C=$country/ST=$state/L=$city/O=$org/OU=$ou/CN=$cn"
}

# ------------------------------------------------------------
# 交互式获取有效期（天数，无默认值，强制输入正整数）
# ------------------------------------------------------------
get_days() {
    local prompt="$1"
    local days
    while true; do
        read -p "$prompt (天数): " days
        if [[ -z "$days" ]]; then
            echo -e "${RED}有效期不能为空，请重新输入。${NC}"
        elif ! [[ "$days" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}请输入正整数。${NC}"
        else
            echo "$days"
            return 0
        fi
    done
}

# ------------------------------------------------------------
# 列出所有根 CA（返回数组 ROOT_DIRS）
# ------------------------------------------------------------
list_roots() {
    ROOT_DIRS=()
    local dirs
    dirs=$(find "$BASE_DIR" -maxdepth 1 -type d -name "*-root" 2>/dev/null | sort)
    if [ -z "$dirs" ]; then
        echo -e "${RED}没有找到根 CA。${NC}"
        return 1
    fi
    local i=1
    for d in $dirs; do
        local name=$(basename "$d")
        echo "$i) $name"
        ROOT_DIRS+=("$d")
        ((i++))
    done
    return 0
}

# ------------------------------------------------------------
# 列出所有可用的签发者（根 + 中间）
# 返回全局数组 ISSUERS，每个元素 "display|path|type"
# ------------------------------------------------------------
list_issuers() {
    ISSUERS=()
    local index=1
    for root_dir in "$BASE_DIR"/*-root; do
        [ -d "$root_dir" ] || continue
        local root_name=$(basename "$root_dir")
        if [ -f "$root_dir/ca.crt" ] && [ -f "$root_dir/ca.key" ]; then
            ISSUERS+=("${index}) [根] $root_name|$root_dir|root")
            ((index++))
        fi
        for int_dir in "$root_dir/intermediates"/*; do
            [ -d "$int_dir" ] || continue
            if [ -f "$int_dir/ca.crt" ] && [ -f "$int_dir/ca.key" ]; then
                local int_name=$(basename "$int_dir")
                ISSUERS+=("${index}) [中间] $root_name/$int_name|$int_dir|intermediate")
                ((index++))
            fi
        done
    done
    if [ ${#ISSUERS[@]} -eq 0 ]; then
        echo -e "${RED}没有可用的签发者。${NC}"
        return 1
    fi
    for item in "${ISSUERS[@]}"; do
        echo "$item" | cut -d'|' -f1
    done
    return 0
}

# ------------------------------------------------------------
# 获取从签发者到根的所有 CA 证书（用于链）
# 用法：get_ca_chain <issuer_dir>  返回数组 CHAIN_CRTS（从叶子到根）
# ------------------------------------------------------------
get_ca_chain() {
    local start_dir="$1"
    CHAIN_CRTS=()
    local current="$start_dir"
    # 先收集当前 CA 证书
    if [ -f "$current/ca.crt" ]; then
        CHAIN_CRTS+=("$current/ca.crt")
    else
        return 1
    fi
    # 向上追溯直到根
    while [[ ! "$(basename "$current")" == *-root ]]; do
        local parent_root_dir=$(dirname "$(dirname "$current")")
        if [ -f "$parent_root_dir/ca.crt" ]; then
            CHAIN_CRTS+=("$parent_root_dir/ca.crt")
            current="$parent_root_dir"
        else
            echo -e "${RED}无法找到上级根 CA 证书。${NC}" >&2
            return 1
        fi
    done
    return 0
}

# ------------------------------------------------------------
# 生成证书信息说明文件
# 用法：generate_info <crt_file> <key_file> <chain_file> <san_list> <info_file>
# ------------------------------------------------------------
generate_info() {
    local crt="$1"
    local key="$2"
    local chain="$3"
    local san_list="$4"
    local info="$5"

    {
        echo "=========================================="
        echo "证书信息摘要"
        echo "=========================================="
        echo "生成时间: $(date)"
        echo ""
        echo "-- 证书主题 --"
        openssl x509 -in "$crt" -noout -subject
        echo ""
        echo "-- 颁发者 --"
        openssl x509 -in "$crt" -noout -issuer
        echo ""
        echo "-- 有效期 --"
        openssl x509 -in "$crt" -noout -dates
        echo ""
        echo "-- 序列号 --"
        openssl x509 -in "$crt" -noout -serial
        echo ""
        echo "-- 公钥信息 --"
        openssl x509 -in "$crt" -noout -pubkey | openssl rsa -pubin -noout -text 2>/dev/null | head -5
        echo ""
        echo "-- SAN（主题备用名称） --"
        if [ -n "$san_list" ]; then
            echo "$san_list"
        else
            openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null || echo "无 SAN 扩展"
        fi
        echo ""
        echo "-- 私钥文件 --"
        echo "$key"
        echo ""
        echo "-- 完整证书链文件 --"
        echo "$chain"
        echo ""
        echo "-- 证书文件 --"
        echo "$crt"
        echo "=========================================="
    } > "$info"
}

# ------------------------------------------------------------
# 创建根 CA
# ------------------------------------------------------------
create_root_ca() {
    echo -e "${GREEN}=== 创建根 CA ===${NC}"
    local root_name
    while [ -z "$root_name" ]; do
        read -p "请输入根 CA 名称（用于目录，如 my-root）: " root_name
        [ -z "$root_name" ] && echo -e "${RED}名称不能为空。${NC}"
    done
    [[ "$root_name" == *-root ]] || root_name="${root_name}-root"

    local root_dir="$BASE_DIR/$root_name"
    if [ -d "$root_dir" ]; then
        echo -e "${YELLOW}目录已存在，是否覆盖？[y/N]${NC}"
        read -p "" ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "已取消。"
            return 0
        fi
        rm -rf "$root_dir"
    fi
    mkdir -p "$root_dir"

    get_subj "$root_name"
    local days=$(get_days "请输入根证书有效期")

    echo -e "${GREEN}生成根 CA 私钥...${NC}"
    openssl genrsa -out "$root_dir/ca.key" $KEY_LEN
    chmod 400 "$root_dir/ca.key"

    echo -e "${GREEN}生成根 CA 自签名证书...${NC}"
    openssl req -new -x509 -key "$root_dir/ca.key" -out "$root_dir/ca.crt" \
        -days "$days" -sha256 -subj "$SUBJ_STRING"

    echo "01" > "$root_dir/ca.srl"
    mkdir -p "$root_dir/certs"
    mkdir -p "$root_dir/intermediates"

    echo -e "${GREEN}根 CA 创建成功！${NC}"
    echo -e "证书: $root_dir/ca.crt"
    echo -e "私钥: $root_dir/ca.key"
}

# ------------------------------------------------------------
# 创建中间 CA
# ------------------------------------------------------------
create_intermediate_ca() {
    echo -e "${GREEN}=== 创建中间 CA ===${NC}"
    echo "请选择签发此中间 CA 的根 CA："
    list_roots || return 1
    local choice
    while true; do
        read -p "请输入序号 [1-${#ROOT_DIRS[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#ROOT_DIRS[@]}" ]; then
            break
        else
            echo -e "${RED}无效选择，请重新输入。${NC}"
        fi
    done
    local parent_dir="${ROOT_DIRS[$((choice-1))]}"

    local int_name
    while [ -z "$int_name" ]; do
        read -p "请输入中间 CA 名称（如 mid1）: " int_name
        [ -z "$int_name" ] && echo -e "${RED}名称不能为空。${NC}"
    done

    local int_dir="$parent_dir/intermediates/$int_name"
    if [ -d "$int_dir" ]; then
        echo -e "${YELLOW}目录已存在，是否覆盖？[y/N]${NC}"
        read -p "" ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "已取消。"
            return 0
        fi
        rm -rf "$int_dir"
    fi
    mkdir -p "$int_dir"

    get_subj "$int_name"
    local days=$(get_days "请输入中间 CA 证书有效期")

    echo -e "${GREEN}生成中间 CA 私钥...${NC}"
    openssl genrsa -out "$int_dir/ca.key" $KEY_LEN
    chmod 400 "$int_dir/ca.key"

    echo -e "${GREEN}生成 CSR...${NC}"
    openssl req -new -key "$int_dir/ca.key" -out "$int_dir/ca.csr" -subj "$SUBJ_STRING"

    echo -e "${GREEN}由根 CA 签发中间证书...${NC}"
    openssl x509 -req -in "$int_dir/ca.csr" \
        -CA "$parent_dir/ca.crt" -CAkey "$parent_dir/ca.key" \
        -CAserial "$parent_dir/ca.srl" \
        -out "$int_dir/ca.crt" -days "$days" -sha256

    rm -f "$int_dir/ca.csr"
    echo "01" > "$int_dir/ca.srl"
    mkdir -p "$int_dir/certs"

    echo -e "${GREEN}中间 CA 创建成功！${NC}"
    echo -e "证书: $int_dir/ca.crt"
    echo -e "私钥: $int_dir/ca.key"
}

# ------------------------------------------------------------
# 创建终端证书（支持 SAN）
# ------------------------------------------------------------
create_cert() {
    echo -e "${GREEN}=== 创建终端证书 ===${NC}"
    echo "请选择签发证书的 CA（根或中间）："
    list_issuers || return 1

    local choice
    while true; do
        read -p "请输入序号 [1-${#ISSUERS[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#ISSUERS[@]}" ]; then
            break
        else
            echo -e "${RED}无效选择，请重新输入。${NC}"
        fi
    done
    local selected="${ISSUERS[$((choice-1))]}"
    local issuer_path=$(echo "$selected" | cut -d'|' -f2)
    local issuer_type=$(echo "$selected" | cut -d'|' -f3)

    local cn
    while [ -z "$cn" ]; do
        read -p "请输入终端证书的通用名 (CN，如 www.example.com 或 IP 地址): " cn
        [ -z "$cn" ] && echo -e "${RED}通用名不能为空。${NC}"
    done

    # 获取 SAN（多个域名/IP，逗号分隔）
    echo -e "${YELLOW}请输入主题备用名称 (SAN)，多个用逗号分隔，例如: DNS:www.example.com,DNS:mail.example.com,IP:192.168.1.1${NC}"
    echo "如果不输入，则默认只使用 CN 作为 SAN。"
    read -p "SAN 列表 (直接回车跳过): " san_input
    local san_list=""
    if [ -n "$san_input" ]; then
        san_list="$san_input"
    else
        # 默认将 CN 作为 SAN（如果 CN 看起来像域名或IP，则自动构造）
        # 简单处理：如果是域名或IP，则生成 DNS:或IP:
        if [[ "$cn" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san_list="IP:$cn"
        else
            san_list="DNS:$cn"
        fi
    fi

    get_subj "$cn"
    local days=$(get_days "请输入终端证书有效期")

    # 创建临时配置文件
    local conf_file=$(mktemp)
    cat > "$conf_file" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = placeholder

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
EOF
    # 解析 SAN 列表并写入
    local idx=1
    IFS=',' read -ra san_array <<< "$san_list"
    for item in "${san_array[@]}"; do
        # 去除前后空格
        item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ "$item" =~ ^DNS: ]] || [[ "$item" =~ ^IP: ]]; then
            echo "DNS.$idx = ${item#*:}" >> "$conf_file"  # 实际应该写成 DNS.1=xxx 但这里简单处理
            # 更正确的方式：
            # 但openssl config中 alt_names 节里需要用 DNS.1, IP.1 等
            # 这里用更通用的写法：直接写 DNS.1 = xxx, IP.1 = yyy
        fi
    done
    # 因为上面简单写法有问题，我们重新正确生成：
    # 重新生成 conf 文件
    cat > "$conf_file" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = placeholder

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
EOF
    idx=1
    IFS=',' read -ra san_array <<< "$san_list"
    for item in "${san_array[@]}"; do
        item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ "$item" =~ ^DNS: ]]; then
            echo "DNS.$idx = ${item#*:}" >> "$conf_file"
            ((idx++))
        elif [[ "$item" =~ ^IP: ]]; then
            echo "IP.$idx = ${item#*:}" >> "$conf_file"
            ((idx++))
        else
            # 如果未加前缀，默认当作 DNS
            echo "DNS.$idx = $item" >> "$conf_file"
            ((idx++))
        fi
    done

    local cert_dir="$issuer_path/certs"
    mkdir -p "$cert_dir"
    local key_file="$cert_dir/$cn.key"
    local csr_file="$cert_dir/$cn.csr"
    local crt_file="$cert_dir/$cn.crt"
    local chain_file="$cert_dir/${cn}-fullchain.crt"
    local info_file="$cert_dir/${cn}.info.txt"

    if [ -f "$crt_file" ] || [ -f "$key_file" ]; then
        echo -e "${YELLOW}证书文件已存在，是否覆盖？[y/N]${NC}"
        read -p "" ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "已取消。"
            rm -f "$conf_file"
            return 0
        fi
        rm -f "$key_file" "$csr_file" "$crt_file" "$chain_file" "$info_file"
    fi

    echo -e "${GREEN}生成终端证书私钥...${NC}"
    openssl genrsa -out "$key_file" $KEY_LEN
    chmod 400 "$key_file"

    echo -e "${GREEN}生成 CSR...${NC}"
    openssl req -new -key "$key_file" -out "$csr_file" -subj "$SUBJ_STRING"

    echo -e "${GREEN}由 ${issuer_type} CA 签发终端证书（含 SAN）...${NC}"
    openssl x509 -req -in "$csr_file" \
        -CA "$issuer_path/ca.crt" -CAkey "$issuer_path/ca.key" \
        -CAserial "$issuer_path/ca.srl" \
        -out "$crt_file" -days "$days" -sha256 \
        -extensions v3_req -extfile "$conf_file"

    rm -f "$csr_file" "$conf_file"

    # 生成完整证书链（终端 + 所有上级 CA）
    get_ca_chain "$issuer_path"
    if [ $? -eq 0 ]; then
        # 注意：CHAIN_CRTS 顺序是从叶子到根（第一个是终端证书？不，我们传入的是issuer_path，所以第一个是签发者自身证书）
        # 我们需要：终端证书在前，然后签发者，然后根
        # 先放终端
        cat "$crt_file" > "$chain_file"
        # 然后依次追加链中的其他 CA（依次是签发者、根）
        for ca_crt in "${CHAIN_CRTS[@]}"; do
            cat "$ca_crt" >> "$chain_file"
        done
        echo -e "完整证书链已生成: $chain_file"
    else
        echo -e "${YELLOW}警告：无法生成完整证书链，可能缺少上级 CA 证书。${NC}"
        # 仅复制自身证书
        cp "$crt_file" "$chain_file"
    fi

    # 生成信息说明文件
    generate_info "$crt_file" "$key_file" "$chain_file" "$san_list" "$info_file"
    echo -e "证书信息说明已生成: $info_file"

    echo -e "${GREEN}终端证书创建成功！${NC}"
    echo -e "证书: $crt_file"
    echo -e "私钥: $key_file"
    echo -e "完整证书链: $chain_file"
    echo -e "信息文件: $info_file"
}

# ------------------------------------------------------------
# 列出所有 CA
# ------------------------------------------------------------
list_all_cas() {
    echo -e "${GREEN}=== 当前 CA 结构 ===${NC}"
    local has=0
    for root_dir in "$BASE_DIR"/*-root; do
        [ -d "$root_dir" ] || continue
        has=1
        local root_name=$(basename "$root_dir")
        echo -e "${YELLOW}根 CA: $root_name${NC}"
        echo "  证书: $root_dir/ca.crt"
        for int_dir in "$root_dir/intermediates"/*; do
            [ -d "$int_dir" ] || continue
            local int_name=$(basename "$int_dir")
            echo "  └── 中间 CA: $int_name"
            echo "      证书: $int_dir/ca.crt"
        done
        if [ -d "$root_dir/certs" ]; then
            local cnt=$(find "$root_dir/certs" -maxdepth 1 -name "*.crt" 2>/dev/null | wc -l)
            [ "$cnt" -gt 0 ] && echo "  直接签发的终端证书: $cnt 个"
        fi
        for int_dir in "$root_dir/intermediates"/*; do
            [ -d "$int_dir/certs" ] || continue
            local int_name=$(basename "$int_dir")
            local cnt=$(find "$int_dir/certs" -maxdepth 1 -name "*.crt" 2>/dev/null | wc -l)
            [ "$cnt" -gt 0 ] && echo "  中间 CA $int_name 签发的终端证书: $cnt 个"
        done
    done
    [ "$has" -eq 0 ] && echo -e "${RED}尚未创建任何 CA。${NC}"
}

# ------------------------------------------------------------
# 主菜单
# ------------------------------------------------------------
while true; do
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}         多级 CA 交互管理             ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo "1. 创建根 CA"
    echo "2. 创建中间 CA（由根签发）"
    echo "3. 创建终端证书（由根或中间签发）"
    echo "4. 列出所有 CA"
    echo "5. 退出"
    read -p "请选择 [1-5]: " menu_choice

    case $menu_choice in
        1) create_root_ca ;;
        2) create_intermediate_ca ;;
        3) create_cert ;;
        4) list_all_cas ;;
        5) echo -e "${GREEN}再见！${NC}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${NC}" ;;
    esac
done