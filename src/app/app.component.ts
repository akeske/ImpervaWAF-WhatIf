import { Component, OnInit } from '@angular/core';
import {
  SecurityRule,
  IPReputationRiskLevelEnum,
  MaliciousIPListEnum,
  ClientTypeEnum,
  VariableEnums,
  RuleSet,
  Token,
} from './model';
import { parseScript } from 'esprima';
import { FormGroup, FormControl, Validators } from '@angular/forms';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  ruleStrings: string[] = [
    'ClientType == HackingTool & ASN != 29241;8075;56910',
    'MaliciousIPList == TorIPs;AnonymousProxyIPs',
    'ClientType == Unknown & ASN != 29241;8075;56910 & ClientIP != 83.212.175.132',
    'IPReputationRiskLevel == High',
    'IPReputationRiskLevel == Medium & CountryCode != GR',
    'ClientType == DDoSBot;Worm;MaskingProxy;ClickBot;CommentSpamBot;SpamBot;VulnerabilityScanner & ClientId != 453',
    '(URL not-contains "oauth";"saml") & (URL not-contains "/dashboard" | ( ClientIP != 62.103.236.223 & ClientIP != 20.50.146.69 & ClientIP != 20.73.36.250 & ClientIP != 62.169.201.60 & ClientIP != 62.103.236.223 & ClientIP != 62.169.197.77))',
  ];
  fakeUser: SecurityRule = {};
  ruless: RuleSet[] = [];

  fakeUserForm = new FormGroup({
    ClientType: new FormControl('', Validators.required),
    IPReputationRiskLevel: new FormControl(''),
    ASN: new FormControl(''),
    CountryCode: new FormControl('GR'),
    ClientIP: new FormControl('62.169.201.60', [
      Validators.required,
      Validators.pattern(
        '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
      ),
    ]),
    ClientId: new FormControl('', [
      Validators.required,
      Validators.min(1),
      Validators.max(985),
    ]),
    URL: new FormControl(''),
    MaliciousIPList: new FormControl(''),
  });

  constructor() {}

  onSubmit(form: FormGroup) {
    this.fakeUser = {
      ClientType: form.value.ClientType,
      IPReputationRiskLevel: form.value.IPReputationRiskLevel,
      ASN: form.value.ASN,
      CountryCode: form.value.CountryCode,
      ClientIP: form.value.ClientIP,
      ClientId: form.value.ClientId,
      URL: form.value.URL,
      MaliciousIPList: form.value.MaliciousIPList,
    };
    this.ruless = [];
    this.parseRules();
  }

  protected evaluate = (node: any): boolean => {
    if (node.type === 'LogicalExpression' || node.type === 'BinaryExpression') {
      const left = this.evaluate(node.left);
      const right = this.evaluate(node.right);
      switch (node.operator) {
        case '&':
          return left && right;
        case '|':
          return left || right;
        default:
          throw new Error(`Unknown operator: ${node.operator}`);
      }
    } else if (node.type === 'UnaryExpression') {
      return !node.argument;
    } else if (node.type === 'ExpressionStatement') {
      return this.evaluate(node.expression);
    } else if (node.type === 'Literal') {
      return node.value;
    } else if (node.type === 'Identifier') {
      // Assume that the identifier refers to a boolean value in the environment.
      return node.value;
    } else {
      throw new Error(`Unknown node type: ${node.type}`);
    }
  };

  protected parseRules(): void {
    const separators = ['&', '\\|', '\\(', '\\)'];
    let res = '';
    this.ruleStrings.forEach(ruleString => {
      let ruleSet: RuleSet = new RuleSet();
      ruleSet.rule = ruleString.replace(/;/g, ' ; ');
      const ruleExpression = ruleString.split(
        new RegExp(separators.join('|'), 'g')
      );
      let operator = '';
      let parenthesis = '';
      ruleExpression.forEach(rule => {
        rule = rule.trim();
        // console.error(rule);
        const ruleTokens = rule.split(new RegExp(' ', 'g'));
        let type = '';
        let vars: string[] = [];
        ruleTokens.forEach(ruleToken => {
          // console.error(ruleToken);
          let isVariable = false;
          let isSpecialChar = false;
          VariableEnums.forEach(variableEnum => {
            if (ruleToken.toLowerCase() === variableEnum.toLowerCase()) {
              type = ruleToken;
              isVariable = true;
            }
          });
          if (ruleToken.trim() == '==' || ruleToken.trim() == '!=') {
            isSpecialChar = true;
            operator = ruleToken.trim();
          }
          if (
            ruleToken.trim() == 'contains' ||
            ruleToken.trim() == 'not-contains'
          ) {
            isSpecialChar = true;
            operator = ruleToken.trim();
          }
          if (ruleToken.trim() == '(' || ruleToken.trim() == ')') {
            isSpecialChar = true;
            parenthesis = ruleToken.trim();
          }
          if (!isVariable && !isSpecialChar) {
            vars = ruleToken.split(new RegExp(';', 'g'));
          }
        });

        const orOperator: any[] = [];
        Object.keys(this.fakeUser).forEach(key => {
          if (type === key) {
            vars.forEach(vari => {
              if (key === type) {
                // console.error(key + ' 1 ' + type);
                // console.error('  ' + type + '-' + operator + ' ' + vari);
                let bool: boolean;
                switch (operator) {
                  case '==':
                    // @ts-expect-error
                    bool = this.fakeUser[key] == vari;
                    break;
                  case '!=':
                    // @ts-expect-error
                    bool = this.fakeUser[key] != vari;
                    break;
                  case 'contains':
                    // @ts-expect-error
                    bool = vari.includes(this.fakeUser[key]);
                    // console.error('  1'+a);
                    break;
                  case 'not-contains':
                    // @ts-expect-error
                    bool = !vari.includes(this.fakeUser[key]);
                    // console.error('  2'+a);
                    break;
                  default:
                    bool = false;
                    break;
                }
                let token: Token = {
                  token: type + ' ' + operator + ' ' + vari,
                  result: bool,
                };
                ruleSet.token.push(token);
                orOperator.push(bool);
              }
            });
          }
        });
        operator = orOperator.join(' | ');
        if (parenthesis === '(') {
          ruleString += ' ( ';
        } else if (parenthesis === ')') {
          ruleString += ' ) ';
        }
        ruleString = ruleString.replace(rule, operator);
      });
      res = ruleString;
      ruleSet.boolExpression = res;

      let ast = parseScript(res);
      let result = this.evaluate(ast.body[0]);
      // console.error(result);
      ruleSet.result = result;
      // console.error('---------------');
      this.ruless.push(ruleSet);
    });
    // console.error(this.ruless);
  }

  ipReputationRiskLevels: IPReputationRiskLevelEnum[] = [
    IPReputationRiskLevelEnum.Low,
    IPReputationRiskLevelEnum.Medium,
    IPReputationRiskLevelEnum.High,
  ];

  clientTypes: ClientTypeEnum[] = [
    ClientTypeEnum.DDoSBot,
    ClientTypeEnum.Worm,
    ClientTypeEnum.MaskingProxy,
    ClientTypeEnum.ClickBot,
    ClientTypeEnum.CommentSpamBot,
    ClientTypeEnum.SpamBot,
    ClientTypeEnum.VulnerabilityScanner,
    ClientTypeEnum.HackingTool,
    ClientTypeEnum.Unknown,
  ];

  MaliciousIPList: MaliciousIPListEnum[] = [
    MaliciousIPListEnum.AnonymousProxyIPs,
    MaliciousIPListEnum.TorIPs,
  ];
}
