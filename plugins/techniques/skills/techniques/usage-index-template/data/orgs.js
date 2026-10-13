// 组织清单。可以直接复用你"家族类型-命令控制表"里 data/orgs.js 的同一套 id,
// 这样两个索引点进同一个组织是一致的,不强制要求,但推荐。
window.FT2 = window.FT2 || { orgs: [], techniques: [], usages: [] };
FT2.addOrg = o => FT2.orgs.push(o);
FT2.addTechnique = t => FT2.techniques.push(t);
FT2.addUsage = u => FT2.usages.push(u);

FT2.addOrg({ id: 'bitter', name: '蔓灵花', aliases: ['Bitter', 'APT-Q-37'] });
FT2.addOrg({ id: 'cnc', name: 'CNC', aliases: ['CNC 组织'] });
