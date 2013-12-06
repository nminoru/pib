pib の特徴

・実行に root 権限は不要。
・HCA が持っている情報が表示できる。
・エラーインジェクションが可能。

pib の制限

・VL による優先順制御はなし。
・SEND Invalidate には対応しない。
・inline_data は無意味
  → ibv_post_send に IBV_SEND_INLINE をつけると L_Key をチェックしなくなる。
・ibv_modify_qp で IB_QP_CUR_STATE を変えるのは禁止
・GRH は使えない。
