#!/bin/bash
export LC_CTYPE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

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
# 列出所有可用的 CA（根和中间），用于选择签发者
# 返回全局数组 CA_LIST，每个元素 "display|path|type"
# ------------------------------------------------------------
list_all_cas_for_issuer() {
    CA_LIST=()
    local index=1
    local ca_dirs=$(find "$BASE_DIR" -type f -name "ca.crt" | xargs -n1 dirname | sort -u)
    for d in $ca_dirs; do
        if [ -f "$d/ca.key" ] && [ -f "$d/ca.crt" ]; then
            if [[ "$(basename "$d")" == *-root ]]; then
                type="根"
            else
                local parent_root=$(basename $(dirname $(dirname "$d")))
                if [[ "$parent_root" == *-root ]]; then
                    type="中间 (由 $parent_root)"
                else
                    type="中间"
                fi
            fi
            local display_name="${type}: $(basename "$d")"
            CA_LIST+=("${index}) $display_name|$d|$type")
            ((index++))
        fi
    done
    if [ ${#CA_LIST[@]} -eq 0 ]; then
        echo -e "${RED}没有找到任何 CA（根或中间）。请先创建根 CA。${NC}"
        return 1
    fi
    for item in "${CA_LIST[@]}"; do
        echo "$item" | cut -d'|' -f1
    done
    return 0
}

# ------------------------------------------------------------
# 获取从某 CA 目录到根的证书链（用于完整链）
# 用法：get_ca_chain <ca_dir>  返回数组 CHAIN_CRTS（从自身到根）
# ------------------------------------------------------------
get_ca_chain() {
    local start_dir="$1"
    CHAIN_CRTS=()
    local current="$start_dir"
    if [ -f "$current/ca.crt" ]; then
        CHAIN_CRTS+=("$current/ca.crt")
    else
        return 1
    fi
    while [[ ! "$(basename "$current")" == *-root ]]; do
        local parent_root_dir=$(dirname "$(dirname "$current")")
        if [ -f "$parent_root_dir/ca.crt" ]; then
            CHAIN_CRTS+=("$parent_root_dir/ca.crt")
            current="$parent_root_dir"
        else
            echo -e "${RED}无法找到上级 CA 证书。${NC}" >&2
            return 1
        fi
    done
    return 0
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
# 创建下级 CA（由任意 CA 签发）
# ------------------------------------------------------------
create_sub_ca() {
    echo -e "${GREEN}=== 创建下级 CA（由已有 CA 签发） ===${NC}"
    echo "请选择签发此新 CA 的父 CA（根或中间）："
    list_all_cas_for_issuer || return 1

    local choice
    while true; do
        read -p "请输入序号 [1-${#CA_LIST[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#CA_LIST[@]}" ]; then
            break
        else
            echo -e "${RED}无效选择，请重新输入。${NC}"
        fi
    done
    local selected="${CA_LIST[$((choice-1))]}"
    local parent_path=$(echo "$selected" | cut -d'|' -f2)
    local parent_type=$(echo "$selected" | cut -d'|' -f3)

    local new_ca_name
    while [ -z "$new_ca_name" ]; do
        read -p "请输入新 CA 的名称（如 mid2，不能与已有 CA 重名）: " new_ca_name
        [ -z "$new_ca_name" ] && echo -e "${RED}名称不能为空。${NC}"
    done

    local new_ca_dir="$parent_path/intermediates/$new_ca_name"
    if [ -d "$new_ca_dir" ]; then
        echo -e "${YELLOW}目录已存在，是否覆盖？[y/N]${NC}"
        read -p "" ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "已取消。"
            return 0
        fi
        rm -rf "$new_ca_dir"
    fi
    mkdir -p "$new_ca_dir"

    get_subj "$new_ca_name"
    local days=$(get_days "请输入新 CA 证书有效期")

    echo -e "${GREEN}生成新 CA 私钥...${NC}"
    openssl genrsa -out "$new_ca_dir/ca.key" $KEY_LEN
    chmod 400 "$new_ca_dir/ca.key"

    echo -e "${GREEN}生成 CSR...${NC}"
    openssl req -new -key "$new_ca_dir/ca.key" -out "$new_ca_dir/ca.csr" -subj "$SUBJ_STRING"

    echo -e "${GREEN}由父 CA 签发新证书...${NC}"
    openssl x509 -req -in "$new_ca_dir/ca.csr" \
        -CA "$parent_path/ca.crt" -CAkey "$parent_path/ca.key" \
        -CAserial "$parent_path/ca.srl" \
        -out "$new_ca_dir/ca.crt" -days "$days" -sha256

    rm -f "$new_ca_dir/ca.csr"
    echo "01" > "$new_ca_dir/ca.srl"
    mkdir -p "$new_ca_dir/certs"

    echo -e "${GREEN}下级 CA 创建成功！${NC}"
    echo -e "证书: $new_ca_dir/ca.crt"
    echo -e "私钥: $new_ca_dir/ca.key"
    echo -e "该 CA 现在可以用于签发更下一级 CA 或终端证书。"
}

# ------------------------------------------------------------
# 创建终端证书（支持 SAN）
# ------------------------------------------------------------
create_cert() {
    echo -e "${GREEN}=== 创建终端证书 ===${NC}"
    echo "请选择签发证书的 CA（根或中间）："
    list_all_cas_for_issuer || return 1

    local choice
    while true; do
        read -p "请输入序号 [1-${#CA_LIST[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#CA_LIST[@]}" ]; then
            break
        else
            echo -e "${RED}无效选择，请重新输入。${NC}"
        fi
    done
    local selected="${CA_LIST[$((choice-1))]}"
    local issuer_path=$(echo "$selected" | cut -d'|' -f2)
    local issuer_type=$(echo "$selected" | cut -d'|' -f3)

    local cn
    while [ -z "$cn" ]; do
        read -p "请输入终端证书的通用名 (CN，如 www.example.com 或 IP 地址): " cn
        [ -z "$cn" ] && echo -e "${RED}通用名不能为空。${NC}"
    done

    echo -e "${YELLOW}请输入主题备用名称 (SAN)，多个用逗号分隔，例如: DNS:www.example.com,DNS:mail.example.com,IP:192.168.1.1${NC}"
    echo "如果不输入，则默认只使用 CN 作为 SAN。"
    read -p "SAN 列表 (直接回车跳过): " san_input
    local san_list=""
    if [ -n "$san_input" ]; then
        san_list="$san_input"
    else
        if [[ "$cn" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san_list="IP:$cn"
        else
            san_list="DNS:$cn"
        fi
    fi

    get_subj "$cn"
    local days=$(get_days "请输入终端证书有效期")

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
    local idx=1
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

    # 生成完整证书链
    get_ca_chain "$issuer_path"
    if [ $? -eq 0 ]; then
        cat "$crt_file" > "$chain_file"
        for ca_crt in "${CHAIN_CRTS[@]}"; do
            cat "$ca_crt" >> "$chain_file"
        done
        echo -e "完整证书链已生成: $chain_file"
    else
        echo -e "${YELLOW}警告：无法生成完整证书链，可能缺少上级 CA 证书。${NC}"
        cp "$crt_file" "$chain_file"
    fi

    # 生成信息文件（关键：添加 -nameopt utf8 解决中文乱码）
    {
        echo "=========================================="
        echo "证书信息摘要"
        echo "=========================================="
        echo "生成时间: $(date)"
        echo ""
        echo "-- 证书主题 --"
        openssl x509 -in "$crt_file" -noout -subject -nameopt utf8
        echo ""
        echo "-- 颁发者 --"
        openssl x509 -in "$crt_file" -noout -issuer -nameopt utf8
        echo ""
        echo "-- 有效期 --"
        openssl x509 -in "$crt_file" -noout -dates
        echo ""
        echo "-- 序列号 --"
        openssl x509 -in "$crt_file" -noout -serial
        echo ""
        echo "-- SAN（主题备用名称） --"
        openssl x509 -in "$crt_file" -noout -ext subjectAltName 2>/dev/null || echo "$san_list"
        echo ""
        echo "-- 私钥文件 --"
        echo "$key_file"
        echo ""
        echo "-- 完整证书链文件 --"
        echo "$chain_file"
        echo ""
        echo "-- 证书文件 --"
        echo "$crt_file"
        echo "=========================================="
    } > "$info_file"

    echo -e "证书信息说明已生成: $info_file"

    echo -e "${GREEN}终端证书创建成功！${NC}"
    echo -e "证书: $crt_file"
    echo -e "私钥: $key_file"
    echo -e "完整证书链: $chain_file"
    echo -e "信息文件: $info_file"
}

# ------------------------------------------------------------
# 列出所有 CA 结构（树形）
# ------------------------------------------------------------
list_all_cas() {
    echo -e "${GREEN}=== 当前 CA 结构 ===${NC}"
    local has=0
    print_tree() {
        local dir="$1"
        local prefix="$2"
        local name=$(basename "$dir")
        if [[ "$name" == *-root ]]; then
            echo -e "${YELLOW}${prefix}根 CA: $name${NC}"
        else
            echo -e "${YELLOW}${prefix}中间 CA: $name${NC}"
        fi
        if [ -d "$dir/intermediates" ]; then
            local sub_dirs=$(find "$dir/intermediates" -maxdepth 1 -type d ! -path "$dir/intermediates" ! -path "$dir/intermediates/*/*" 2>/dev/null | sort)
            for sub in $sub_dirs; do
                if [ -f "$sub/ca.crt" ]; then
                    print_tree "$sub" "  $prefix"
                fi
            done
        fi
        if [ -d "$dir/certs" ]; then
            local cnt=$(find "$dir/certs" -maxdepth 1 -name "*.crt" 2>/dev/null | wc -l)
            [ "$cnt" -gt 0 ] && echo "  ${prefix}签发的终端证书: $cnt 个"
        fi
    }

    for root_dir in "$BASE_DIR"/*-root; do
        [ -d "$root_dir" ] || continue
        has=1
        print_tree "$root_dir" ""
    done
    if [ "$has" -eq 0 ]; then
        echo -e "${RED}尚未创建任何 CA。${NC}"
    fi
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
    echo "2. 创建下级 CA（由任意已有 CA 签发）"
    echo "3. 创建终端证书（由任意 CA 签发）"
    echo "4. 列出所有 CA 结构"
    echo "5. 退出"
    read -p "请选择 [1-5]: " menu_choice

    case $menu_choice in
        1) create_root_ca ;;
        2) create_sub_ca ;;
        3) create_cert ;;
        4) list_all_cas ;;
        5) echo -e "${GREEN}再见！${NC}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请重新选择。${NC}" ;;
    esac
done