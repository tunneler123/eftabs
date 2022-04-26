menu() {
  update_sh
  shell_mode_check
  echo -e "\t Xray 安装管理脚本 ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by wulabing---"
  echo -e "\thttps://github.com/wulabing\n"

  echo -e "当前已安装版本：${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 Xray (VLESS + TCP + XTLS / TLS + Nginx)"
  echo -e "${Green}2.${Font}  安装 Xray (VLESS + TCP + XTLS / TLS + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket 回落并存模式)"
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 变更 UUID"
  echo -e "${Green}13.${Font} 变更 连接端口"
  echo -e "${Green}14.${Font} 变更 WebSocket PATH"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 Xray 配置链接"
  #    echo -e "${Green}23.${Font}  查看 V2Ray 配置信息"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}31.${Font} 安装 4 合 1 BBR、锐速安装脚本"
  echo -e "${Yellow}32.${Font} 安装 MTproxy （不推荐使用,请相关用户关闭或卸载）"
  echo -e "${Green}33.${Font} 卸载 Xray"
  echo -e "${Green}34.${Font} 更新 Xray-core"
  echo -e "${Green}35.${Font} 安装 Xray-core 测试版 (Pre)"
  echo -e "${Green}36.${Font} 手动更新 SSL 证书"
  echo -e "${Green}40.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "请输入 UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "请输入路径(示例：/wulabing/ 要求两侧都包含 /):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "当前模式不是 Websocket 模式"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "xray 配置文件不存在"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    source '/etc/os-release'
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  36)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
